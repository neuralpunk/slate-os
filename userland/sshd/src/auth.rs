// SPDX-License-Identifier: MIT OR Apache-2.0

//! User authentication (RFC 4252): the `publickey` method with Ed25519
//! keys from `~/.ssh/authorized_keys` (OpenSSH's file format: one
//! `ssh-ed25519 BASE64 comment` per line), and the `password` method
//! against /etc/shadow (SHA-512 crypt). Accounts with an empty or locked
//! password cannot log in by password.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_coreutils::crypt;
use slate_rt::{fs, lossy};

use crate::crypto;
use crate::wire::{Reader, Writer};

/// An account from /etc/passwd (passwd(5)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    /// Logged in with a key, but the password has expired: the session
    /// changes it first (ADR 0143).
    pub expired: bool,
}

pub fn parse_passwd(text: &str, name: &str) -> Option<User> {
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 7 && f[0] == name).then(|| User {
            name: f[0].into(),
            uid: f[2].parse().unwrap_or(u32::MAX),
            gid: f[3].parse().unwrap_or(u32::MAX),
            home: f[5].into(),
            shell: if f[6].is_empty() { "/bin/sh".into() } else { f[6].into() },
            expired: false,
        })
    })
}

pub fn lookup(name: &str) -> Option<User> {
    let text = fs::read_file(b"/etc/passwd").ok()?;
    parse_passwd(&lossy(&text), name)
}

/// The Ed25519 key blobs in an authorized_keys file's text.
pub fn authorized_blobs(text: &str) -> Vec<Vec<u8>> {
    text.lines()
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            // Lines may start with options; the key type marks the key.
            let ty = parts.by_ref().find(|p| *p == "ssh-ed25519")?;
            let _ = ty;
            crate::wire::unbase64(parts.next()?.as_bytes())
        })
        .collect()
}

/// Root's (or anyone's) hash in /etc/shadow text.
pub fn shadow_hash(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == name).then(|| f.next().unwrap_or("").into())
    })
}

/// A password check: never for empty or locked (`!`, `*`) hashes.
pub fn password_ok(hash: &str, password: &[u8]) -> bool {
    if hash.is_empty() || hash.starts_with('!') || hash.starts_with('*') {
        return false;
    }
    crypt::verify(password, hash.as_bytes())
}

/// What a USERAUTH_REQUEST asked and whether it succeeded.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Logged in.
    Success(User),
    /// The client asked whether a key would do; it would (PK_OK).
    KeyAcceptable {
        algorithm: Vec<u8>,
        blob: Vec<u8>,
    },
    /// A password change (RFC 4252 §8) with the right old password.
    Change {
        user: User,
        old: Vec<u8>,
        new: Vec<u8>,
    },
    Failure,
}

/// Where the keys of `user` live: `template` with `%h` for the home
/// directory, `%u` for the name and `%%` for `%`; a relative path is
/// from the home directory (sshd_config(5) AuthorizedKeysFile).
pub fn keys_path(template: &str, user: &User) -> String {
    let p = template.replace("%%", "\0").replace("%h", &user.home).replace("%u", &user.name).replace('\0', "%");
    if p.starts_with('/') { p } else { format!("{}/{p}", user.home.trim_end_matches('/')) }
}

/// Decide a USERAUTH_REQUEST (`msg` without its message number).
pub fn decide(
    msg: &[u8],
    session_id: &[u8],
    keys_files: &[String],
    find_user: &dyn Fn(&str) -> Option<User>,
    read: &dyn Fn(&str) -> Option<String>,
) -> Outcome {
    let mut r = Reader::new(msg);
    let (Ok(user), Ok(service), Ok(method)) = (r.string(), r.string(), r.string()) else { return Outcome::Failure };
    let name = String::from_utf8_lossy(user).into_owned();
    if service != b"ssh-connection" {
        return Outcome::Failure;
    }
    let Some(u) = find_user(&name) else { return Outcome::Failure };
    match method {
        b"publickey" => {
            let (Ok(has_sig), Ok(alg), Ok(blob)) = (r.bool(), r.string(), r.string()) else { return Outcome::Failure };
            if alg != crypto::HOST_KEY {
                return Outcome::Failure;
            }
            let keys: Vec<Vec<u8>> =
                keys_files.iter().filter_map(|f| read(&keys_path(f, &u))).flat_map(|t| authorized_blobs(&t)).collect();
            if !keys.iter().any(|k| k == blob) {
                return Outcome::Failure;
            }
            if !has_sig {
                return Outcome::KeyAcceptable { algorithm: alg.to_vec(), blob: blob.to_vec() };
            }
            let Ok(sig) = r.string() else { return Outcome::Failure };
            // The key blob and the signature blob both start with the
            // algorithm name (RFC 8709 §4-§6).
            let mut kb = Reader::new(blob);
            let mut sb = Reader::new(sig);
            let (Ok(b"ssh-ed25519"), Ok(pk)) = (kb.string(), kb.string()) else { return Outcome::Failure };
            let (Ok(b"ssh-ed25519"), Ok(raw)) = (sb.string(), sb.string()) else { return Outcome::Failure };
            // What was signed (RFC 4252 §7).
            let signed = Writer::default()
                .string(session_id)
                .byte(crate::session::MSG_USERAUTH_REQUEST)
                .string(user)
                .string(b"ssh-connection")
                .string(b"publickey")
                .bool(true)
                .string(alg)
                .string(blob)
                .finish();
            if crypto::ed25519_verify(pk, &signed, raw) { Outcome::Success(u) } else { Outcome::Failure }
        }
        b"password" => {
            let (Ok(change), Ok(pw)) = (r.bool(), r.string()) else { return Outcome::Failure };
            let new = if change {
                match r.string() {
                    Ok(n) if !n.is_empty() => Some(n.to_vec()),
                    _ => return Outcome::Failure,
                }
            } else {
                None
            };
            let shadow = read("/etc/shadow").unwrap_or_default();
            match (shadow_hash(&shadow, &name), new) {
                (Some(h), None) if password_ok(&h, pw) => Outcome::Success(u),
                (Some(h), Some(new)) if password_ok(&h, pw) => Outcome::Change { user: u, old: pw.to_vec(), new },
                _ => Outcome::Failure,
            }
        }
        _ => Outcome::Failure,
    }
}

/// `SHA256:...` as OpenSSH prints key fingerprints.
pub fn fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", crate::wire::base64(&crypto::sha256(blob), false))
}
