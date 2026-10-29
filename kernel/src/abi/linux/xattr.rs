// SPDX-License-Identifier: MIT OR Apache-2.0

//! Extended attributes (xattr(7)): the get/set/list/remove system calls in
//! their path, no-follow and file-descriptor forms, and the permission rules
//! of each attribute namespace.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::errno::*;
use super::fs::user_path;
use super::{Args, Result};
use crate::arch::uaccess::{copy_from_user, copy_to_user, read_user_cstr};
use crate::fs::vfs::{self, Dentry, FileType};
use crate::proc::cred::{CAP_SETFCAP, CAP_SYS_ADMIN, MAY_READ, MAY_WRITE};

/// XATTR_NAME_MAX, XATTR_SIZE_MAX and XATTR_LIST_MAX (xattr(7), limits.h).
const NAME_MAX: usize = 255;
const SIZE_MAX: usize = 65536;
const LIST_MAX: usize = 65536;

/// How the file is named: a path (following the last symlink or not) or a
/// descriptor.
#[derive(Clone, Copy)]
enum Target {
    Path(u64, bool),
    Fd(i32),
}

fn resolve(t: Target) -> core::result::Result<Arc<Dentry>, Errno> {
    let p = crate::proc::current().ok_or(ESRCH)?;
    match t {
        Target::Path(addr, follow) => {
            let path = user_path(addr)?;
            vfs::resolve(&p.cwd(), &path, follow)
        }
        Target::Fd(fd) => p.files.lock().get(fd)?.dentry().ok_or(EBADF),
    }
}

fn read_name(addr: u64) -> core::result::Result<String, Errno> {
    let bytes = read_user_cstr(addr, NAME_MAX + 1).map_err(|_| ERANGE)?;
    if bytes.is_empty() || bytes.len() > NAME_MAX {
        return Err(ERANGE);
    }
    String::from_utf8(bytes).map_err(|_| EINVAL)
}

#[derive(PartialEq)]
enum Access {
    Read,
    Write,
}

/// The rules per namespace (xattr(7)): `user.` follows the file's
/// permission bits and exists only on regular files and directories;
/// `trusted.` needs CAP_SYS_ADMIN; writing `security.` needs CAP_SYS_ADMIN
/// (CAP_SETFCAP for `security.capability`); `system.` (POSIX ACLs) is not
/// supported.
fn check(d: &Dentry, name: &str, access: Access) -> core::result::Result<(), Errno> {
    let cred = crate::proc::cred::current();
    let meta = d.metadata();
    if name.starts_with("user.") {
        let ft = meta.file_type();
        if ft != FileType::Regular && ft != FileType::Directory {
            return Err(if access == Access::Read { ENODATA } else { EPERM });
        }
        if access == Access::Write
            && meta.mode & crate::proc::cred::S_ISVTX != 0
            && ft == FileType::Directory
            && !cred.owns(&meta)
        {
            return Err(EPERM);
        }
        return cred.permission(&meta, if access == Access::Read { MAY_READ } else { MAY_WRITE });
    }
    if name.starts_with("trusted.") {
        return if cred.capable(CAP_SYS_ADMIN) {
            Ok(())
        } else if access == Access::Read {
            Err(ENODATA)
        } else {
            Err(EPERM)
        };
    }
    if name.starts_with("security.") {
        if access == Access::Read {
            return Ok(());
        }
        let cap = if name == "security.capability" { CAP_SETFCAP } else { CAP_SYS_ADMIN };
        return if cred.capable_wrt(&meta, cap) { Ok(()) } else { Err(EPERM) };
    }
    Err(EOPNOTSUPP)
}

/// A name as the native calls give it (pointer and length).
pub(crate) fn check_name(bytes: Vec<u8>) -> core::result::Result<String, Errno> {
    if bytes.is_empty() || bytes.len() > NAME_MAX {
        return Err(ERANGE);
    }
    String::from_utf8(bytes).map_err(|_| EINVAL)
}

/// Set an attribute (the calls' shared core).
pub(crate) fn set_value(d: &Arc<Dentry>, name: &str, mut value: Vec<u8>, flags: u32) -> Result {
    if value.len() > SIZE_MAX {
        return Err(E2BIG);
    }
    if flags & !(vfs::XATTR_CREATE | vfs::XATTR_REPLACE) != 0 {
        return Err(EINVAL);
    }
    vfs::writable(d)?;
    check(d, name, Access::Write)?;
    // File capabilities name the user namespace they were set in.
    if name == crate::proc::fcaps::NAME {
        value = crate::proc::fcaps::on_write(&value, &crate::proc::cred::current())?;
    }
    d.inode.set_xattr(name, &value, flags)?;
    Ok(0)
}

/// An attribute's value.
pub(crate) fn get_value(d: &Dentry, name: &str) -> core::result::Result<Vec<u8>, Errno> {
    check(d, name, Access::Read)?;
    let value = d.inode.get_xattr(name)?;
    if name == crate::proc::fcaps::NAME {
        return Ok(crate::proc::fcaps::on_read(value, &crate::proc::cred::current()));
    }
    Ok(value)
}

/// The names the caller may read, each ending in a zero byte.
pub(crate) fn list_names(d: &Dentry) -> core::result::Result<Vec<u8>, Errno> {
    let mut out: Vec<u8> = Vec::new();
    for n in d.inode.list_xattr()? {
        if check(d, &n, Access::Read).is_ok() {
            out.extend_from_slice(n.as_bytes());
            out.push(0);
        }
    }
    if out.len() > LIST_MAX {
        return Err(E2BIG);
    }
    Ok(out)
}

pub(crate) fn remove_value(d: &Arc<Dentry>, name: &str) -> Result {
    vfs::writable(d)?;
    check(d, name, Access::Write)?;
    d.inode.remove_xattr(name)?;
    Ok(0)
}

/// The file an open descriptor names.
pub(crate) fn fd_dentry(fd: i32) -> core::result::Result<Arc<Dentry>, Errno> {
    resolve(Target::Fd(fd))
}

fn do_set(t: Target, a: &Args) -> Result {
    let name = read_name(a.0[1])?;
    let size = a.0[3] as usize;
    if size > SIZE_MAX {
        return Err(E2BIG);
    }
    let mut value = alloc::vec![0u8; size];
    if size > 0 {
        copy_from_user(&mut value, a.0[2]).map_err(|_| EFAULT)?;
    }
    let d = resolve(t)?;
    set_value(&d, &name, value, a.0[4] as u32)
}

fn do_get(t: Target, a: &Args) -> Result {
    let name = read_name(a.0[1])?;
    let d = resolve(t)?;
    let value = get_value(&d, &name)?;
    let size = a.0[3] as usize;
    if size == 0 {
        return Ok(value.len() as u64);
    }
    if value.len() > size {
        return Err(ERANGE);
    }
    copy_to_user(a.0[2], &value).map_err(|_| EFAULT)?;
    Ok(value.len() as u64)
}

fn do_list(t: Target, a: &Args) -> Result {
    let d = resolve(t)?;
    // Names the caller may not read are left out.
    let out = list_names(&d)?;
    let size = a.0[2] as usize;
    if size == 0 {
        return Ok(out.len() as u64);
    }
    if out.len() > size {
        return Err(ERANGE);
    }
    copy_to_user(a.0[1], &out).map_err(|_| EFAULT)?;
    Ok(out.len() as u64)
}

fn do_remove(t: Target, a: &Args) -> Result {
    let name = read_name(a.0[1])?;
    let d = resolve(t)?;
    remove_value(&d, &name)
}

pub fn setxattr(a: Args) -> Result {
    do_set(Target::Path(a.0[0], true), &a)
}
pub fn lsetxattr(a: Args) -> Result {
    do_set(Target::Path(a.0[0], false), &a)
}
pub fn fsetxattr(a: Args) -> Result {
    do_set(Target::Fd(a.fd(0)), &a)
}
pub fn getxattr(a: Args) -> Result {
    do_get(Target::Path(a.0[0], true), &a)
}
pub fn lgetxattr(a: Args) -> Result {
    do_get(Target::Path(a.0[0], false), &a)
}
pub fn fgetxattr(a: Args) -> Result {
    do_get(Target::Fd(a.fd(0)), &a)
}
pub fn listxattr(a: Args) -> Result {
    do_list(Target::Path(a.0[0], true), &a)
}
pub fn llistxattr(a: Args) -> Result {
    do_list(Target::Path(a.0[0], false), &a)
}
pub fn flistxattr(a: Args) -> Result {
    do_list(Target::Fd(a.fd(0)), &a)
}
pub fn removexattr(a: Args) -> Result {
    do_remove(Target::Path(a.0[0], true), &a)
}
pub fn lremovexattr(a: Args) -> Result {
    do_remove(Target::Path(a.0[0], false), &a)
}
pub fn fremovexattr(a: Args) -> Result {
    do_remove(Target::Fd(a.fd(0)), &a)
}
