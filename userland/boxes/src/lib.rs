// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux boxes (ADR 0183): a Linux distribution (Arch Linux) in a box of
//! its own, where software published as source builds with its usual
//! commands, apart from SlateOS.
//!
//! - [`daemon`] is `slate-boxd` (root, a service): it fetches a
//!   distribution and checks it against its maker's key, makes the base
//!   ([`base`]) and the boxes (SlateFS subvolumes with IDs of their own,
//!   [`ids`]), mounts them, and writes a box session's ID maps. It answers
//!   Slate's own programs only, over [`proto`].
//! - [`cli`] is `slate-box`, the person's command: `create`, `enter`,
//!   `run`, `list`, `remove`, `distros`.
//! - [`session`] enters a box: namespaces of its own, a PID 1 of Slate's
//!   own, the box's root, and the shell or the command as the box's user.
//! - [`distro`] reads `/usr/share/slate/boxes/NAME.distro`.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod agent;
pub mod base;
pub mod channel;
pub mod cli;
pub mod daemon;
pub mod distro;
pub mod host;
pub mod ids;
pub mod native;
pub mod proto;
pub mod receipts;
pub mod session;

/// Where the boxes are: `UID/NAME` each, the bases in `.base`, slate-boxd's
/// own state in `.state`. A SlateFS (the root's on installed systems).
pub const BOXES: &str = "/var/lib/slate/boxes";
/// slate-boxd's state: the ID ranges given out, finished bases.
pub const STATE: &str = "/var/lib/slate/boxes/.state";
/// Where the bases are mounted.
pub const BASES: &str = "/var/lib/slate/boxes/.base";
/// slate-boxd's socket.
pub const SOCKET: &str = "/run/slate-boxd.sock";

/// The longest box name (the kernel's tag takes 32 bytes, slate_abi's
/// `box_tag::NAME_MAX`).
pub const NAME_MAX: usize = 32;

/// Whether `name` can name a box: 1 to 32 lower-case letters, digits and
/// `-`, starting with a letter or digit (it becomes the box's host name
/// and part of a subvolume's name).
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_MAX
        && name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        && !name.starts_with('-')
}

/// The person's (name, primary group) from Slate's /etc/passwd.
pub fn account(uid: u32) -> Option<(alloc::string::String, u32)> {
    let text = slate_rt::fs::read_file(b"/etc/passwd").ok()?;
    account_in(&slate_rt::lossy(&text), uid)
}

/// The person's home folder, from Slate's /etc/passwd.
pub fn home_of(uid: u32) -> Option<alloc::string::String> {
    let text = slate_rt::fs::read_file(b"/etc/passwd").ok()?;
    slate_rt::lossy(&text).lines().find_map(|l| {
        let f: alloc::vec::Vec<&str> = l.split(':').collect();
        (f.len() >= 6 && f[2].parse() == Ok(uid)).then(|| alloc::string::String::from(f[5]))
    })
}

/// [`account`] in passwd(5)'s text.
pub fn account_in(passwd: &str, uid: u32) -> Option<(alloc::string::String, u32)> {
    passwd.lines().find_map(|l| {
        let f: alloc::vec::Vec<&str> = l.split(':').collect();
        (f.len() >= 4 && f[2].parse() == Ok(uid))
            .then(|| (alloc::string::String::from(f[0]), f[3].parse().unwrap_or(uid)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["dev", "a", "my-box-2", "0x"] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", "-x", "Dev", "a b", "a/b", "a.b", "abcdefghijabcdefghijabcdefghijabc"] {
            assert!(!valid_name(bad), "{bad}");
        }
        let pw = "root:x:0:0::/root:/bin/sh\nada:x:1000:1000:Ada:/home/ada:/bin/sh\n";
        assert_eq!(account_in(pw, 1000), Some(("ada".into(), 1000)));
        assert_eq!(account_in(pw, 7), None);
    }
}
