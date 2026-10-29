// SPDX-License-Identifier: MIT OR Apache-2.0

//! The user databases: /etc/passwd (passwd(5)), /etc/group (group(5)),
//! /etc/shadow (shadow(5)) and /etc/gshadow (gshadow(5)).

use alloc::vec::Vec;

use slate_rt::{Errno, fs, process};

pub const PASSWD: &[u8] = b"/etc/passwd";
pub const GROUP: &[u8] = b"/etc/group";
pub const SHADOW: &[u8] = b"/etc/shadow";
pub const GSHADOW: &[u8] = b"/etc/gshadow";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct User {
    pub name: Vec<u8>,
    /// The passwd file's password field (`x` when the hash is in shadow).
    pub passwd: Vec<u8>,
    pub uid: u32,
    pub gid: u32,
    pub gecos: Vec<u8>,
    pub home: Vec<u8>,
    pub shell: Vec<u8>,
}

fn fields(line: &[u8]) -> Vec<&[u8]> {
    line.split(|&c| c == b':').collect()
}

fn num(b: &[u8]) -> Option<u32> {
    core::str::from_utf8(b).ok()?.parse().ok()
}

pub fn parse_users(data: &[u8]) -> Vec<User> {
    data.split(|&c| c == b'\n')
        .filter_map(|l| {
            let f = fields(l);
            if f.len() < 7 {
                return None;
            }
            Some(User {
                name: f[0].to_vec(),
                passwd: f[1].to_vec(),
                uid: num(f[2])?,
                gid: num(f[3])?,
                gecos: f[4].to_vec(),
                home: f[5].to_vec(),
                shell: f[6].to_vec(),
            })
        })
        .collect()
}

pub fn users() -> Vec<User> {
    fs::read_file(PASSWD).map(|d| parse_users(&d)).unwrap_or_default()
}

pub fn user_by_name(name: &[u8]) -> Option<User> {
    users().into_iter().find(|u| u.name == name)
}

pub fn user_by_uid(uid: u32) -> Option<User> {
    users().into_iter().find(|u| u.uid == uid)
}

/// The groups `user` belongs to: its primary group and every group that
/// lists it as a member.
pub fn groups_of(user: &User) -> Vec<u32> {
    let mut g = alloc::vec![user.gid];
    if let Ok(data) = fs::read_file(GROUP) {
        for l in data.split(|&c| c == b'\n') {
            let f = fields(l);
            if f.len() < 4 {
                continue;
            }
            let Some(gid) = num(f[2]) else { continue };
            if f[3].split(|&c| c == b',').any(|m| m == user.name.as_slice()) && !g.contains(&gid) {
                g.push(gid);
            }
        }
    }
    g
}

/// The ID of the group called `name`.
pub fn group_id(name: &[u8]) -> Option<u32> {
    let data = fs::read_file(GROUP).ok()?;
    data.split(|&c| c == b'\n').find_map(|l| {
        let f = fields(l);
        (f.len() >= 4 && f[0] == name).then(|| num(f[2])).flatten()
    })
}

/// The name of group `gid`.
pub fn group_name(gid: u32) -> Option<Vec<u8>> {
    let data = fs::read_file(GROUP).ok()?;
    data.split(|&c| c == b'\n').find_map(|l| {
        let f = fields(l);
        (f.len() >= 4 && num(f[2]) == Some(gid)).then(|| f[0].to_vec())
    })
}

/// The password hash of `user`: from shadow when passwd says `x`.
pub fn hash_of(user: &User) -> Option<Vec<u8>> {
    if user.passwd != b"x" {
        return Some(user.passwd.clone());
    }
    let data = fs::read_file(SHADOW).ok()?;
    data.split(|&c| c == b'\n').find_map(|l| {
        let f = fields(l);
        (f.first() == Some(&user.name.as_slice()) && f.len() >= 2).then(|| f[1].to_vec())
    })
}

/// A group's gshadow(5) entry: its password hash (empty, `!` or `*`:
/// none) and the members it lists.
pub fn gshadow_of(name: &[u8]) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
    let data = fs::read_file(GSHADOW).ok()?;
    data.split(|&c| c == b'\n').find_map(|l| {
        let f = fields(l);
        (f.len() >= 4 && f[0] == name).then(|| {
            let members = f[3].split(|&c| c == b',').filter(|m| !m.is_empty()).map(<[u8]>::to_vec).collect();
            (f[1].to_vec(), members)
        })
    })
}

/// The administrators gshadow(5) gives group `name`.
pub fn group_admins(name: &[u8]) -> Vec<Vec<u8>> {
    let Ok(data) = fs::read_file(GSHADOW) else { return Vec::new() };
    data.split(|&c| c == b'\n')
        .find_map(|l| {
            let f = fields(l);
            (f.len() >= 4 && f[0] == name)
                .then(|| f[2].split(|&c| c == b',').filter(|m| !m.is_empty()).map(<[u8]>::to_vec).collect())
        })
        .unwrap_or_default()
}

/// Days since the epoch, for shadow's "last change" field.
pub fn today() -> u64 {
    (slate_rt::time::unix() / 86400) as u64
}

/// Replace `user`'s shadow entry with `hash` (atomically: a new file
/// renamed over the old one).
pub fn set_hash(name: &[u8], hash: &[u8]) -> Result<(), Errno> {
    let data = fs::read_file(SHADOW).unwrap_or_default();
    let mut out = Vec::new();
    let mut found = false;
    for l in data.split(|&c| c == b'\n').filter(|l| !l.is_empty()) {
        let mut f: Vec<Vec<u8>> = fields(l).into_iter().map(<[u8]>::to_vec).collect();
        if f.first().map(Vec::as_slice) == Some(name) {
            found = true;
            f.resize(f.len().max(9), Vec::new());
            f[1] = hash.to_vec();
            f[2] = alloc::format!("{}", today()).into_bytes();
        }
        out.extend_from_slice(&f.join(&b':'));
        out.push(b'\n');
    }
    if !found {
        out.extend_from_slice(name);
        out.push(b':');
        out.extend_from_slice(hash);
        out.extend_from_slice(alloc::format!(":{}:0:99999:7:::\n", today()).as_bytes());
    }
    let tmp = alloc::format!("/etc/.shadow.{}", process::getpid()).into_bytes();
    fs::write_file(&tmp, &out, 0o600)?;
    let r = fs::chmod(&tmp, 0o600).and_then(|()| fs::rename(&tmp, SHADOW));
    if r.is_err() {
        let _ = fs::unlink(&tmp);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        let u = parse_users(b"root:x:0:0:root:/root:/bin/sh\nbad line\nuser:x:1000:100:A user:/home/user:/bin/chalk\n");
        assert_eq!(u.len(), 2);
        assert_eq!(u[1].name, b"user");
        assert_eq!(u[1].uid, 1000);
        assert_eq!(u[1].shell, b"/bin/chalk");
    }
}
