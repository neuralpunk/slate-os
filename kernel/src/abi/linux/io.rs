// SPDX-License-Identifier: MIT OR Apache-2.0

//! read(2), write(2), readv(2), writev(2), pread(2), pwrite(2), close(2),
//! ioctl(2).

use alloc::vec;

use super::errno::{EFAULT, EINVAL, ESRCH};
use super::{Args, Result};
use crate::arch::uaccess::{copy_from_user, copy_to_user, read_user};
use crate::fs::{File, O_NONBLOCK};
use crate::proc;

/// Largest chunk copied through a kernel buffer at once.
const CHUNK: usize = 64 * 1024;
/// The most one read or write moves (read(2) and write(2), NOTES: Linux
/// transfers at most 0x7ffff000 bytes, returning the count moved).
const MAX_RW_COUNT: u64 = 0x7fff_f000;

/// A file operation's result.
type Io<T> = core::result::Result<T, super::Errno>;
/// `IOV_MAX` (readv(2)).
const IOV_MAX: u64 = 1024;

fn file(fd: i32) -> core::result::Result<alloc::sync::Arc<dyn File>, super::Errno> {
    proc::current().ok_or(ESRCH)?.files.lock().get(fd)
}

/// O_DIRECT's buffers and lengths are multiples of the file's alignment
/// (open(2): EINVAL; the offset is the file's to check, ADR 0162).
fn direct_ok(f: &dyn File, bufs: &[(u64, u64)]) -> Io<()> {
    match f.direct_align() {
        Some(a) if bufs.iter().any(|&(base, len)| base % a != 0 || len % a != 0) => Err(EINVAL),
        _ => Ok(()),
    }
}

/// One read of up to `len` bytes: `read(k, done)` reads the next part
/// into `k` and `put(k, done)` hands it to the caller. A single read of at
/// most `CHUNK`, or for files whose reads never wait (`File::fills_reads`)
/// as many as fill `len` or reach the end. An error after some bytes came
/// reports those bytes.
fn read_chunks(
    f: &dyn File,
    len: u64,
    read: impl FnMut(&mut [u8], u64) -> Io<usize>,
    put: impl FnMut(&[u8], u64) -> Io<()>,
) -> Result {
    let r = read_chunks_inner(f, len, read, put);
    account(|c| &c.syscr, |c| &c.rchar, &r);
    r
}

/// Count a read or write call, and the bytes it moved, for the thread and
/// its process (/proc/PID/io).
fn account(
    calls: fn(&crate::proc::Counts) -> &core::sync::atomic::AtomicU64,
    bytes: fn(&crate::proc::Counts) -> &core::sync::atomic::AtomicU64,
    r: &Result,
) {
    if crate::sched::started() {
        let t = crate::sched::current();
        t.count(calls, 1);
        if let Ok(n) = r {
            t.count(bytes, *n);
        }
    }
}

fn read_chunks_inner(
    f: &dyn File,
    len: u64,
    mut read: impl FnMut(&mut [u8], u64) -> Io<usize>,
    mut put: impl FnMut(&[u8], u64) -> Io<()>,
) -> Result {
    let len = len.min(f.read_limit()).min(MAX_RW_COUNT);
    let mut k = vec![0u8; (len as usize).min(CHUNK)];
    let mut done = 0u64;
    loop {
        let want = ((len - done) as usize).min(CHUNK);
        let n = match read(&mut k[..want], done) {
            Ok(n) => n,
            Err(_) if done > 0 => break,
            Err(e) => return Err(e),
        };
        put(&k[..n], done)?;
        done += n as u64;
        if n < want || done >= len || !f.fills_reads() {
            break;
        }
    }
    Ok(done)
}

fn read_into(f: &dyn File, buf: u64, len: u64) -> Result {
    let to_user = |k: &[u8], done: u64| copy_to_user(buf + done, k).map_err(|_| EFAULT);
    read_chunks(f, len, |k, _| f.read(k), to_user)
}

/// Write `data` in chunks. An error after some bytes went out (a full
/// non-blocking pipe, a signal) reports those bytes instead (write(2)):
/// the caller must not send them again.
fn write_chunks(f: &dyn File, next: impl FnMut(&mut alloc::vec::Vec<u8>, u64) -> Result, len: u64) -> Result {
    write_chunks_with(f, next, |k, _| f.write(k), len)
}

/// [`write_chunks`], each chunk written by `write(k, done)`.
fn write_chunks_with(
    f: &dyn File,
    next: impl FnMut(&mut alloc::vec::Vec<u8>, u64) -> Result,
    write: impl FnMut(&[u8], u64) -> Io<usize>,
    len: u64,
) -> Result {
    let r = write_chunks_inner(f, next, write, len);
    account(|c| &c.syscw, |c| &c.wchar, &r);
    r
}

fn write_chunks_inner(
    f: &dyn File,
    mut next: impl FnMut(&mut alloc::vec::Vec<u8>, u64) -> Result,
    mut write: impl FnMut(&[u8], u64) -> Io<usize>,
    len: u64,
) -> Result {
    let len = len.min(MAX_RW_COUNT);
    let mut done = 0u64;
    let mut k = alloc::vec::Vec::new();
    // Watches on the file hear of the write (inotify(7)).
    let _modified = Modified(f);
    while done < len {
        k.resize(((len - done) as usize).min(CHUNK), 0);
        next(&mut k, done)?;
        let w = match write(&k, done) {
            Ok(w) => w,
            Err(_) if done > 0 => break,
            Err(e) => return Err(e),
        };
        done += w as u64;
        if w < k.len() {
            break;
        }
    }
    Ok(done)
}

fn write_from(f: &dyn File, buf: u64, len: u64) -> Result {
    write_chunks(f, |k, done| copy_from_user(k, buf + done).map(|()| 0).map_err(|_| EFAULT), len)
}

pub fn read(a: Args) -> Result {
    let f = file(a.fd(0))?;
    direct_ok(&*f, &[(a.0[1], a.0[2])])?;
    read_into(&*f, a.0[1], a.0[2])
}

pub fn write(a: Args) -> Result {
    let f = file(a.fd(0))?;
    direct_ok(&*f, &[(a.0[1], a.0[2])])?;
    write_from(&*f, a.0[1], a.0[2])
}

/// `struct iovec` (readv(2)).
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Iovec {
    base: u64,
    len: u64,
}

fn iovecs(addr: u64, count: u64) -> core::result::Result<alloc::vec::Vec<Iovec>, super::Errno> {
    if count > IOV_MAX {
        return Err(EINVAL);
    }
    let v: alloc::vec::Vec<Iovec> = (0..count)
        .map(|i| read_user::<Iovec>(addr + i * 16).map_err(|_| EFAULT))
        .collect::<core::result::Result<_, _>>()?;
    // readv(2): EINVAL if the lengths add up past what an ssize_t holds.
    v.iter().try_fold(0u64, |t, x| t.checked_add(x.len).filter(|&t| t <= i64::MAX as u64)).ok_or(EINVAL)?;
    Ok(v)
}

/// readv(2): as read(2), scattered over the buffers: one read, or for
/// files whose reads never wait as many as fill them (a second read of a
/// pipe could block after the first returned data).
pub fn readv(a: Args) -> Result {
    let f = file(a.fd(0))?;
    let iov = iovecs(a.0[1], a.0[2])?;
    direct_ok(&*f, &iov.iter().map(|v| (v.base, v.len)).collect::<alloc::vec::Vec<_>>())?;
    let total: u64 = iov.iter().map(|v| v.len).sum();
    let scatter = |k: &[u8], done: u64| -> Io<()> {
        // Bytes `done..done + k.len()` of the whole go where they belong.
        let (mut pos, mut taken) = (0u64, 0usize);
        for v in &iov {
            let (start, end) = (pos, pos + v.len);
            pos = end;
            let at = done + taken as u64;
            if end <= at || taken == k.len() {
                continue;
            }
            let off = at - start;
            let m = ((v.len - off) as usize).min(k.len() - taken);
            copy_to_user(v.base + off, &k[taken..taken + m]).map_err(|_| EFAULT)?;
            taken += m;
        }
        Ok(())
    };
    read_chunks(&*f, total, |k, _| f.read(k), scatter)
}

/// pread(2): as read(2), from `offset` (a negative one is EINVAL).
pub fn pread64(a: Args) -> Result {
    let f = file(a.fd(0))?;
    let (buf, len, offset) = (a.0[1], a.0[2], a.0[3]);
    if (offset as i64) < 0 {
        return Err(EINVAL);
    }
    direct_ok(&*f, &[(buf, len)])?;
    let to_user = |k: &[u8], done: u64| copy_to_user(buf + done, k).map_err(|_| EFAULT);
    read_chunks(&*f, len, |k, done| f.pread(offset + done, k), to_user)
}

/// pwrite(2): as write(2), at `offset`.
pub fn pwrite64(a: Args) -> Result {
    let f = file(a.fd(0))?;
    let (buf, len, offset) = (a.0[1], a.0[2], a.0[3]);
    if (offset as i64) < 0 {
        return Err(EINVAL);
    }
    direct_ok(&*f, &[(buf, len)])?;
    let from_user =
        |k: &mut alloc::vec::Vec<u8>, done: u64| copy_from_user(k, buf + done).map(|()| 0).map_err(|_| EFAULT);
    write_chunks_with(&*f, from_user, |k, done| f.pwrite(offset + done, k), len)
}

/// writev(2): the buffers are gathered and written as one write, so small
/// writes to pipes stay atomic.
pub fn writev(a: Args) -> Result {
    let f = file(a.fd(0))?;
    let iov = iovecs(a.0[1], a.0[2])?;
    direct_ok(&*f, &iov.iter().map(|v| (v.base, v.len)).collect::<alloc::vec::Vec<_>>())?;
    let total: u64 = iov.iter().map(|v| v.len).sum();
    write_chunks(
        &*f,
        |k, done| {
            // Fill `k` with bytes `done..done + k.len()` of the gathered data.
            let (mut pos, mut filled) = (0u64, 0usize);
            for v in &iov {
                let (start, end) = (pos, pos + v.len);
                pos = end;
                let want = done + filled as u64;
                if end <= want || filled == k.len() {
                    continue;
                }
                let off = want - start;
                let m = ((v.len - off) as usize).min(k.len() - filled);
                copy_from_user(&mut k[filled..filled + m], v.base + off).map_err(|_| EFAULT)?;
                filled += m;
            }
            Ok(0)
        },
        total,
    )
}

pub fn close(a: Args) -> Result {
    let p = proc::current().ok_or(ESRCH)?;
    let watched = if crate::fs::inotify::active() { p.files.lock().get(a.fd(0)).ok() } else { None };
    p.files.lock().close(a.fd(0))?;
    // IN_CLOSE_WRITE or IN_CLOSE_NOWRITE for watches on a file closed.
    if let Some(f) = watched
        && let Some(d) = f.dentry()
    {
        let writable = f.status_flags() & crate::fs::O_ACCMODE != crate::fs::O_RDONLY;
        let mask = if writable { crate::fs::inotify::IN_CLOSE_WRITE } else { crate::fs::inotify::IN_CLOSE_NOWRITE };
        crate::fs::inotify::report_self(&d, mask);
    }
    Ok(0)
}

/// Reports IN_MODIFY when a write to a watched file ends (written or not:
/// a failed write changes nothing, but inotify(7) allows spurious events).
struct Modified<'a>(&'a dyn File);

impl Drop for Modified<'_> {
    fn drop(&mut self) {
        if crate::fs::inotify::active()
            && let Some(d) = self.0.dentry()
            && d.metadata().mode & crate::fs::vfs::S_IFMT == crate::fs::vfs::S_IFREG
        {
            crate::fs::inotify::report_self(&d, crate::fs::inotify::IN_MODIFY);
        }
    }
}

pub fn ioctl(a: Args) -> Result {
    use super::ioctl::{FIOCLEX, FIONBIO, FIONCLEX};
    let fd = a.fd(0);
    // The file-descriptor ioctls that apply to every kind of file
    // (ioctl(2), ioctl_tty(2) "FIONBIO"; fcntl(2) equivalents).
    match a.0[1] as u32 {
        FIONBIO => {
            let on: i32 = read_user(a.0[2]).map_err(|_| EFAULT)?;
            let f = file(fd)?;
            let flags = f.status_flags();
            f.set_status_flags(if on != 0 { flags | O_NONBLOCK } else { flags & !O_NONBLOCK });
            Ok(0)
        }
        FIOCLEX | FIONCLEX => {
            let p = crate::proc::current().ok_or(ESRCH)?;
            p.files.lock().set_cloexec(fd, a.0[1] as u32 == FIOCLEX)?;
            Ok(0)
        }
        req => file(fd)?.ioctl(req, a.0[2]),
    }
}

/// sendfile(2): copy between descriptors through a kernel buffer.
pub fn sendfile(a: Args) -> Result {
    let (out, inp) = (file(a.fd(0))?, file(a.fd(1))?);
    let (off_ptr, count) = (a.0[2], a.0[3] as usize);
    let mut offset: Option<u64> = if off_ptr != 0 { Some(read_user(off_ptr).map_err(|_| EFAULT)?) } else { None };
    let mut k = vec![0u8; count.min(CHUNK)];
    let mut done = 0usize;
    while done < count {
        let want = (count - done).min(CHUNK);
        // An error after some progress ends the call with that progress.
        let got = match offset {
            Some(o) => inp.pread(o, &mut k[..want]),
            None => inp.read(&mut k[..want]),
        };
        let n = match got {
            Ok(n) => n,
            Err(_) if done > 0 => break,
            Err(e) => return Err(e),
        };
        if n == 0 {
            break;
        }
        let w = match out.write(&k[..n]) {
            Ok(w) => w,
            Err(_) if done > 0 => break,
            Err(e) => return Err(e),
        };
        done += w;
        if let Some(o) = offset.as_mut() {
            *o += w as u64;
        }
        if w < n {
            break;
        }
    }
    if let Some(o) = offset {
        crate::arch::uaccess::write_user(off_ptr, &o).map_err(|_| EFAULT)?;
    }
    Ok(done as u64)
}

/// copy_file_range(2): copy `len` bytes between two regular files, from
/// and to their offsets (or the pointed-to ones, which are updated), as
/// many reads and writes (ADR 0114: OSTree and GLib copy files so).
pub fn copy_file_range(a: Args) -> Result {
    use crate::fs::vfs::FileType;
    use crate::fs::{O_ACCMODE, O_APPEND, O_PATH, O_RDONLY, O_WRONLY};
    let (inp, out) = (file(a.fd(0))?, file(a.fd(2))?);
    let (in_ptr, out_ptr, len, flags) = (a.0[1], a.0[3], a.0[4] as usize, a.0[5]);
    if flags != 0 {
        return Err(EINVAL);
    }
    let (fi, fo) = (inp.status_flags(), out.status_flags());
    if fi & O_PATH != 0
        || fo & O_PATH != 0
        || fi & O_ACCMODE == O_WRONLY
        || fo & O_ACCMODE == O_RDONLY
        || fo & O_APPEND != 0
    {
        return Err(super::errno::EBADF);
    }
    let regular = |f: &alloc::sync::Arc<dyn File>| f.stat().is_ok_and(|m| m.file_type() == FileType::Regular);
    if !regular(&inp) || !regular(&out) {
        return Err(EINVAL);
    }
    let mut off_in: Option<u64> = if in_ptr != 0 { Some(read_user(in_ptr).map_err(|_| EFAULT)?) } else { None };
    let mut off_out: Option<u64> = if out_ptr != 0 { Some(read_user(out_ptr).map_err(|_| EFAULT)?) } else { None };
    let mut k = vec![0u8; len.min(CHUNK)];
    let mut done = 0usize;
    while done < len {
        let want = (len - done).min(CHUNK);
        let got = match off_in {
            Some(o) => inp.pread(o, &mut k[..want]),
            None => inp.read(&mut k[..want]),
        };
        let n = match got {
            Ok(n) => n,
            Err(_) if done > 0 => break,
            Err(e) => return Err(e),
        };
        if n == 0 {
            break;
        }
        let put = match off_out {
            Some(o) => out.pwrite(o, &k[..n]),
            None => out.write(&k[..n]),
        };
        let w = match put {
            Ok(w) => w,
            Err(_) if done > 0 => break,
            Err(e) => return Err(e),
        };
        done += w;
        if let Some(o) = off_in.as_mut() {
            *o += w as u64;
        }
        if let Some(o) = off_out.as_mut() {
            *o += w as u64;
        }
        if w < n {
            break;
        }
    }
    for (ptr, off) in [(in_ptr, off_in), (out_ptr, off_out)] {
        if let Some(o) = off {
            crate::arch::uaccess::write_user(ptr, &o).map_err(|_| EFAULT)?;
        }
    }
    Ok(done as u64)
}
