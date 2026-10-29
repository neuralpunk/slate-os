// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signed programs (ADR 0090): the keys the kernel trusts, built in, and
//! the check of a program's signature trailer (`libs/elfsign`) at exec,
//! remembered per file.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use slate_elfsign::{Digest, Keyring, PublicKey, TRAILER, Trailer};
use slate_sync::Once;

use crate::abi::linux::errno::Errno;
use crate::fs::vfs::Dentry;
use crate::sync::IrqSpinLock;

/// The public keys the kernel was built with (`SLATE_TRUSTED_KEYS`), one
/// `quarry-public-key` line each; none in a build without them.
static TRUSTED: &str = include_str!(concat!(env!("OUT_DIR"), "/trusted.keys"));

static KEYS: Once<Keyring> = Once::new();

fn keyring() -> &'static Keyring {
    KEYS.call_once(|| {
        let keys: Vec<PublicKey> = TRUSTED.lines().filter_map(|l| PublicKey::parse(l).ok()).collect();
        crate::log_info!("sign: {} trusted key(s)", keys.len());
        Keyring::new(keys)
    })
}

/// A file as it was when checked: device, inode, size, change and
/// modification times.
type FileKey = (u64, u64, u64, (i64, i64), (i64, i64));

/// What checks found: the flags of a good signature, or none.
static CHECKED: IrqSpinLock<BTreeMap<FileKey, Option<u32>>> = IrqSpinLock::new(BTreeMap::new());
/// A bound on the files remembered.
const MAX_CHECKED: usize = 4096;
/// Programs are read in pieces of this size.
const CHUNK: usize = 64 << 10;

/// The flags of the program's signature if a key the kernel trusts signed
/// it, else None.
pub fn flags_of(d: &Dentry, read: impl Fn(u64, &mut [u8]) -> Result<(), Errno>) -> Result<Option<u32>, Errno> {
    let m = d.metadata();
    let key: FileKey = (m.dev, m.ino, m.size, (m.mtime.sec, m.mtime.nsec), (m.ctime.sec, m.ctime.nsec));
    if let Some(r) = CHECKED.lock().get(&key) {
        return Ok(*r);
    }
    let r = check(m.size, &read)?;
    let mut c = CHECKED.lock();
    if c.len() >= MAX_CHECKED {
        c.clear();
    }
    c.insert(key, r);
    Ok(r)
}

fn check(size: u64, read: &impl Fn(u64, &mut [u8]) -> Result<(), Errno>) -> Result<Option<u32>, Errno> {
    let Some(at) = size.checked_sub(TRAILER as u64) else { return Ok(None) };
    let mut t = [0u8; TRAILER];
    read(at, &mut t)?;
    let Some(t) = Trailer::parse(&t) else { return Ok(None) };
    let keys = keyring();
    let mut d = Digest::new();
    let mut buf = alloc::vec![0u8; CHUNK];
    let mut off = 0;
    while off < at {
        let n = (at - off).min(CHUNK as u64) as usize;
        read(off, &mut buf[..n])?;
        d.update(&buf[..n]);
        off += n as u64;
    }
    Ok(slate_elfsign::check(&t, &d.finish(&t.header()), keys).ok())
}
