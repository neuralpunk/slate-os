// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sockets for C (ADR 0075): <sys/socket.h>, <netinet/in.h>,
//! <arpa/inet.h>, <netdb.h>, <poll.h> and <sys/select.h>, on slate-rt's
//! socket calls. Address layouts, families, levels, options and message
//! flags are Linux's, which Slate's native interface shares (socket(7),
//! ip(7), ipv6(7), unix(7), tcp(7)). Names are resolved with
//! slate-resolve: literals, /etc/hosts, then DNS.
//!
//! Not here (docs/GAPS.md): sendmsg/recvmsg with control messages,
//! getnameinfo's reverse lookups, gethostbyaddr, and service names beyond
//! /etc/services and a few built in.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;

use slate_net::{IpAddr, Ipv4, Ipv6};
use slate_rt::{Errno, io, net::raw};

use crate::{cstr, ret, set_errno};

/// C's `ssize_t` result: the count, or -1 with errno set.
fn sret(r: slate_rt::Result<usize>) -> isize {
    match r {
        Ok(n) => n as isize,
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

/// The bytes of an address C passes, or None for a null pointer.
///
/// # Safety
///
/// `addr` must be null or point to `len` readable bytes.
unsafe fn addr_in<'a>(addr: *const u8, len: u32) -> Option<&'a [u8]> {
    // SAFETY: Forwarded from the caller.
    (!addr.is_null()).then(|| unsafe { core::slice::from_raw_parts(addr, len as usize) })
}

/// Copy an address out to C's buffer and length (truncating as POSIX
/// says, but reporting the full length).
///
/// # Safety
///
/// `addr` must be null or hold `*len` bytes; `len` null or valid.
unsafe fn addr_out(full: &[u8], addr: *mut u8, len: *mut u32) {
    if addr.is_null() || len.is_null() {
        return;
    }
    // SAFETY: Forwarded from the caller.
    unsafe {
        let room = (*len as usize).min(full.len());
        core::ptr::copy_nonoverlapping(full.as_ptr(), addr, room);
        *len = full.len() as u32;
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn socket(family: c_int, kind: c_int, protocol: c_int) -> c_int {
    ret(raw::socket(family, kind, protocol))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn socketpair(family: c_int, kind: c_int, protocol: c_int, fds: *mut c_int) -> c_int {
    match raw::socketpair(family, kind, protocol) {
        Ok([a, b]) => {
            // SAFETY: C passes room for two descriptors.
            unsafe {
                *fds = a;
                *fds.add(1) = b;
            }
            0
        }
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn bind(fd: c_int, addr: *const u8, len: u32) -> c_int {
    // SAFETY: C passes `len` bytes of address.
    ret(raw::bind(fd, unsafe { addr_in(addr, len) }.unwrap_or(&[])).map(|_| 0))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn connect(fd: c_int, addr: *const u8, len: u32) -> c_int {
    // SAFETY: As for bind.
    ret(raw::connect(fd, unsafe { addr_in(addr, len) }.unwrap_or(&[])).map(|_| 0))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn listen(fd: c_int, backlog: c_int) -> c_int {
    ret(raw::listen(fd, backlog).map(|_| 0))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn accept4(fd: c_int, addr: *mut u8, len: *mut u32, flags: c_int) -> c_int {
    let mut buf = [0u8; 128];
    match raw::accept(fd, &mut buf, flags) {
        Ok((c, n)) => {
            // SAFETY: C's buffer and length (or nulls).
            unsafe { addr_out(&buf[..n.min(128)], addr, len) };
            c
        }
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn accept(fd: c_int, addr: *mut u8, len: *mut u32) -> c_int {
    // SAFETY: Forwarded.
    unsafe { accept4(fd, addr, len, 0) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn sendto(
    fd: c_int,
    buf: *const c_void,
    n: usize,
    flags: c_int,
    addr: *const u8,
    len: u32,
) -> isize {
    // SAFETY: C passes `n` bytes of data and null or an address.
    unsafe { sret(raw::send_to(fd, core::slice::from_raw_parts(buf as *const u8, n), flags, addr_in(addr, len))) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn send(fd: c_int, buf: *const c_void, n: usize, flags: c_int) -> isize {
    // SAFETY: Forwarded.
    unsafe { sendto(fd, buf, n, flags, core::ptr::null(), 0) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn recvfrom(
    fd: c_int,
    buf: *mut c_void,
    n: usize,
    flags: c_int,
    addr: *mut u8,
    len: *mut u32,
) -> isize {
    let mut from = [0u8; 128];
    // SAFETY: C passes room for `n` bytes.
    let data = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, n) };
    match raw::recv_from(fd, data, flags, if addr.is_null() { None } else { Some(&mut from) }) {
        Ok((got, alen)) => {
            if !addr.is_null() {
                // SAFETY: C's buffer and length.
                unsafe { addr_out(&from[..alen.min(128)], addr, len) };
            }
            got as isize
        }
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn recv(fd: c_int, buf: *mut c_void, n: usize, flags: c_int) -> isize {
    // SAFETY: Forwarded.
    unsafe { recvfrom(fd, buf, n, flags, null_mut(), null_mut()) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn setsockopt(fd: c_int, level: c_int, name: c_int, value: *const c_void, len: u32) -> c_int {
    // SAFETY: C passes `len` bytes of value.
    let v = unsafe { addr_in(value as *const u8, len) }.unwrap_or(&[]);
    ret(raw::set_opt(fd, level, name, v).map(|_| 0))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn getsockopt(fd: c_int, level: c_int, name: c_int, value: *mut c_void, len: *mut u32) -> c_int {
    // SAFETY: C passes `*len` bytes of room.
    let room = unsafe { core::slice::from_raw_parts_mut(value as *mut u8, *len as usize) };
    match raw::get_opt(fd, level, name, room) {
        Ok(n) => {
            // SAFETY: As above.
            unsafe { *len = n as u32 };
            0
        }
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn shutdown(fd: c_int, how: c_int) -> c_int {
    ret(raw::shutdown(fd, how).map(|_| 0))
}

unsafe fn name_of(fd: c_int, addr: *mut u8, len: *mut u32, peer: bool) -> c_int {
    let mut buf = [0u8; 128];
    match raw::name(fd, &mut buf, peer) {
        Ok(n) => {
            // SAFETY: C's buffer and length.
            unsafe { addr_out(&buf[..n.min(128)], addr, len) };
            0
        }
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn getsockname(fd: c_int, addr: *mut u8, len: *mut u32) -> c_int {
    // SAFETY: Forwarded.
    unsafe { name_of(fd, addr, len, false) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn getpeername(fd: c_int, addr: *mut u8, len: *mut u32) -> c_int {
    // SAFETY: Forwarded.
    unsafe { name_of(fd, addr, len, true) }
}

// --- byte order and addresses -------------------------------------------------

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn htons(v: u16) -> u16 {
    v.to_be()
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn ntohs(v: u16) -> u16 {
    u16::from_be(v)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn htonl(v: u32) -> u32 {
    v.to_be()
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn ntohl(v: u32) -> u32 {
    u32::from_be(v)
}

pub const AF_UNSPEC: c_int = 0;
pub const AF_UNIX: c_int = 1;
pub const AF_INET: c_int = 2;
pub const AF_INET6: c_int = 10;
/// in6addr_any and in6addr_loopback (ipv6(7)).
#[allow(non_upper_case_globals)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub static in6addr_any: [u8; 16] = [0; 16];
#[allow(non_upper_case_globals)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub static in6addr_loopback: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

const SOCK_STREAM: c_int = 1;
const SOCK_DGRAM: c_int = 2;
const SOCK_RAW: c_int = 3;
const IPPROTO_TCP: c_int = 6;
const IPPROTO_UDP: c_int = 17;

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_pton(family: c_int, src: *const c_char, dst: *mut c_void) -> c_int {
    // SAFETY: C passes a string and room for the address.
    let text = core::str::from_utf8(unsafe { cstr(src) }).unwrap_or("");
    match family {
        AF_INET => match strict_v4(text) {
            Some(a) => {
                // SAFETY: Room for 4 bytes.
                unsafe { core::ptr::copy_nonoverlapping(a.as_ptr(), dst as *mut u8, 4) };
                1
            }
            None => 0,
        },
        AF_INET6 => match Ipv6::parse(text) {
            Some(a) => {
                // SAFETY: Room for 16 bytes.
                unsafe { core::ptr::copy_nonoverlapping(a.0.as_ptr(), dst as *mut u8, 16) };
                1
            }
            None => 0,
        },
        _ => {
            set_errno(Errno::EAFNOSUPPORT);
            -1
        }
    }
}

/// inet_pton's IPv4 form: exactly four decimal numbers 0-255.
fn strict_v4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = s.split('.');
    for o in out.iter_mut() {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0'))
        {
            return None;
        }
        *o = p.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_ntop(family: c_int, src: *const c_void, dst: *mut c_char, size: u32) -> *const c_char {
    let text = match family {
        // SAFETY: C passes 4 or 16 bytes of address.
        AF_INET => alloc::format!("{}", Ipv4(unsafe { *(src as *const [u8; 4]) })),
        // SAFETY: As above.
        AF_INET6 => alloc::format!("{}", Ipv6(unsafe { *(src as *const [u8; 16]) })),
        _ => {
            set_errno(Errno::EAFNOSUPPORT);
            return core::ptr::null();
        }
    };
    if text.len() + 1 > size as usize {
        set_errno(Errno::ENOSPC);
        return core::ptr::null();
    }
    // SAFETY: `dst` holds `size` bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(text.as_ptr(), dst as *mut u8, text.len());
        *dst.add(text.len()) = 0;
    }
    dst
}

/// inet_aton's forms (inet(3)): a, a.b, a.b.c or a.b.c.d, each part
/// decimal, octal (0...) or hexadecimal (0x...).
fn aton(s: &[u8]) -> Option<u32> {
    let mut parts: Vec<u64> = Vec::new();
    for p in s.split(|&c| c == b'.') {
        let (digits, base) = if p.len() > 1 && (p[1] | 0x20) == b'x' && p[0] == b'0' {
            (&p[2..], 16)
        } else if p.len() > 1 && p[0] == b'0' {
            (&p[1..], 8)
        } else {
            (p, 10)
        };
        if digits.is_empty() && base != 8 {
            return None;
        }
        let mut v: u64 = 0;
        for &c in digits {
            v = v * base + u64::from((c as char).to_digit(base as u32)?);
            if v > u64::from(u32::MAX) {
                return None;
            }
        }
        parts.push(v);
    }
    let last_max = |n: usize| (1u64 << (8 * (5 - n))) - 1;
    match parts.len() {
        1 => Some(parts[0] as u32),
        n @ 2..=4 if parts[..n - 1].iter().all(|&p| p <= 255) && parts[n - 1] <= last_max(n) => {
            let mut v = 0u64;
            for &p in &parts[..n - 1] {
                v = v << 8 | p;
            }
            Some((v << (8 * (5 - n)) | parts[n - 1]) as u32)
        }
        _ => None,
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_aton(s: *const c_char, out: *mut u32) -> c_int {
    // SAFETY: C passes a string.
    match aton(unsafe { cstr(s) }) {
        Some(v) => {
            if !out.is_null() {
                // SAFETY: Room for an `in_addr`.
                unsafe { *out = v.to_be() };
            }
            1
        }
        None => 0,
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_addr(s: *const c_char) -> u32 {
    // SAFETY: C passes a string. INADDR_NONE on failure.
    unsafe { aton(cstr(s)) }.map_or(u32::MAX, u32::to_be)
}

#[thread_local]
static NTOA: core::cell::UnsafeCell<[u8; 16]> = core::cell::UnsafeCell::new([0; 16]);

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn inet_ntoa(a: u32) -> *mut c_char {
    let text = alloc::format!("{}", Ipv4(a.to_ne_bytes()));
    let buf = NTOA.get() as *mut u8;
    // SAFETY: The calling thread's own 16 bytes; the text is at most 15.
    unsafe {
        core::ptr::copy_nonoverlapping(text.as_ptr(), buf, text.len());
        *buf.add(text.len()) = 0;
    }
    buf as *mut c_char
}

// --- poll and select ----------------------------------------------------------

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn poll(fds: *mut io::PollFd, n: u64, timeout: c_int) -> c_int {
    // SAFETY: C passes `n` pollfd structures.
    let list = unsafe { core::slice::from_raw_parts_mut(fds, n as usize) };
    ret(io::poll(list, timeout))
}

/// `fd_set`: FD_SETSIZE (1024) bits.
#[repr(C)]
pub struct FdSet {
    bits: [u64; 16],
}

const POLLIN: i16 = 1;
const POLLPRI: i16 = 2;
const POLLOUT: i16 = 4;
const POLLERR: i16 = 8;
const POLLHUP: i16 = 0x10;

fn has(set: *mut FdSet, fd: usize) -> bool {
    // SAFETY: Callers pass null or a valid set.
    unsafe { set.as_ref() }.is_some_and(|s| s.bits[fd / 64] >> (fd % 64) & 1 == 1)
}

/// select(2) over poll: each descriptor in the sets becomes one poll
/// entry, and the sets come back holding the ready ones.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn select(
    n: c_int,
    r: *mut FdSet,
    w: *mut FdSet,
    e: *mut FdSet,
    timeout: *mut [i64; 2],
) -> c_int {
    if !(0..=1024).contains(&n) {
        set_errno(Errno::EINVAL);
        return -1;
    }
    let mut list = Vec::new();
    for fd in 0..n as usize {
        let ev = if has(r, fd) { POLLIN } else { 0 }
            | if has(w, fd) { POLLOUT } else { 0 }
            | if has(e, fd) { POLLPRI } else { 0 };
        if ev != 0 {
            list.push(io::PollFd { fd: fd as i32, events: ev, revents: 0 });
        }
    }
    // SAFETY: C passes null or a `struct timeval`.
    let ms = match unsafe { timeout.as_ref() } {
        None => -1,
        Some(&[s, us]) => {
            (s.saturating_mul(1000).saturating_add((us + 999) / 1000)).clamp(0, i64::from(i32::MAX)) as i32
        }
    };
    let got = match io::poll(&mut list, ms) {
        Ok(_) => 0,
        Err(err) => {
            set_errno(err);
            return -1;
        }
    };
    let _ = got;
    for set in [r, w, e] {
        // SAFETY: C passes null or a valid set.
        if let Some(s) = unsafe { set.as_mut() } {
            s.bits = [0; 16];
        }
    }
    let mut count = 0;
    let mark = |set: *mut FdSet, fd: i32| {
        // SAFETY: As above.
        if let Some(s) = unsafe { set.as_mut() } {
            s.bits[fd as usize / 64] |= 1 << (fd % 64);
        }
    };
    for p in &list {
        if p.events & POLLIN != 0 && p.revents & (POLLIN | POLLHUP | POLLERR) != 0 {
            mark(r, p.fd);
            count += 1;
        }
        if p.events & POLLOUT != 0 && p.revents & (POLLOUT | POLLERR) != 0 {
            mark(w, p.fd);
            count += 1;
        }
        if p.events & POLLPRI != 0 && p.revents & POLLPRI != 0 {
            mark(e, p.fd);
            count += 1;
        }
    }
    count
}

// --- names ----------------------------------------------------------------------

/// `struct addrinfo` (POSIX order).
#[repr(C)]
pub struct AddrInfo {
    flags: c_int,
    family: c_int,
    socktype: c_int,
    protocol: c_int,
    addrlen: u32,
    addr: *mut u8,
    canonname: *mut c_char,
    next: *mut AddrInfo,
}

/// One result: the `addrinfo` first, so its pointer is the entry's.
#[repr(C)]
struct Entry {
    ai: AddrInfo,
    storage: [u8; 28],
    name: Option<Box<[u8]>>,
}

const AI_PASSIVE: c_int = 1;
const AI_CANONNAME: c_int = 2;
const AI_NUMERICHOST: c_int = 4;
const AI_NUMERICSERV: c_int = 0x400;

const EAI_BADFLAGS: c_int = -1;
const EAI_NONAME: c_int = -2;
const EAI_AGAIN: c_int = -3;
const EAI_FAIL: c_int = -4;
const EAI_FAMILY: c_int = -6;
const EAI_SOCKTYPE: c_int = -7;
const EAI_SERVICE: c_int = -8;
const EAI_SYSTEM: c_int = -11;
const EAI_OVERFLOW: c_int = -12;

/// Services every system knows, when /etc/services does not say.
const SERVICES: &[(&str, u16)] = &[
    ("ftp", 21),
    ("ssh", 22),
    ("telnet", 23),
    ("smtp", 25),
    ("domain", 53),
    ("http", 80),
    ("pop3", 110),
    ("ntp", 123),
    ("imap", 143),
    ("https", 443),
    ("submission", 587),
    ("imaps", 993),
    ("pop3s", 995),
];

/// A service name or number as a port.
fn service_port(s: &str, numeric_only: bool) -> Option<u16> {
    if let Ok(p) = s.parse::<u16>() {
        return Some(p);
    }
    if numeric_only {
        return None;
    }
    if let Ok(text) = slate_rt::fs::read_file(b"/etc/services") {
        for line in String::from_utf8_lossy(&text).lines() {
            let line = line.split('#').next().unwrap_or("");
            let mut f = line.split_whitespace();
            let (Some(name), Some(pp)) = (f.next(), f.next()) else { continue };
            if (name == s || f.any(|a| a == s))
                && let Some(p) = pp.split('/').next().and_then(|p| p.parse().ok())
            {
                return Some(p);
            }
        }
    }
    SERVICES.iter().find(|(n, _)| *n == s).map(|&(_, p)| p)
}

/// A `sockaddr_in` or `sockaddr_in6`.
fn sockaddr(a: &IpAddr, port: u16) -> ([u8; 28], u32, c_int) {
    let mut b = [0u8; 28];
    match a {
        IpAddr::V4(v) => {
            b[..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
            b[2..4].copy_from_slice(&port.to_be_bytes());
            b[4..8].copy_from_slice(&v.0);
            (b, 16, AF_INET)
        }
        IpAddr::V6(v) => {
            b[..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
            b[2..4].copy_from_slice(&port.to_be_bytes());
            b[8..24].copy_from_slice(&v.0);
            (b, 28, AF_INET6)
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const AddrInfo,
    res: *mut *mut AddrInfo,
) -> c_int {
    // SAFETY: C passes null or a hints structure.
    let (flags, family, socktype, protocol) = match unsafe { hints.as_ref() } {
        Some(h) => (h.flags, h.family, h.socktype, h.protocol),
        None => (0, AF_UNSPEC, 0, 0),
    };
    if flags & !(AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST | AI_NUMERICSERV | 0x08 | 0x10 | 0x20) != 0 {
        return EAI_BADFLAGS;
    }
    if !matches!(family, AF_UNSPEC | AF_INET | AF_INET6) {
        return EAI_FAMILY;
    }
    if !matches!(socktype, 0 | SOCK_STREAM | SOCK_DGRAM | SOCK_RAW) {
        return EAI_SOCKTYPE;
    }
    if node.is_null() && service.is_null() {
        return EAI_NONAME;
    }
    let port = if service.is_null() {
        0
    } else {
        // SAFETY: A NUL-terminated string.
        let s = String::from_utf8_lossy(unsafe { cstr(service) }).into_owned();
        match service_port(&s, flags & AI_NUMERICSERV != 0) {
            Some(p) => p,
            None => return EAI_SERVICE,
        }
    };
    let want = match family {
        AF_INET => slate_resolve::Family::V4,
        AF_INET6 => slate_resolve::Family::V6,
        _ => slate_resolve::Family::Any,
    };
    let (addrs, canon) = if node.is_null() {
        // No node: the wildcard to listen on, or loopback to connect to.
        let passive = flags & AI_PASSIVE != 0;
        let mut v = Vec::new();
        if family != AF_INET {
            v.push(IpAddr::V6(if passive { Ipv6::UNSPECIFIED } else { Ipv6::LOCALHOST }));
        }
        if family != AF_INET6 {
            v.push(IpAddr::V4(Ipv4(if passive { [0; 4] } else { [127, 0, 0, 1] })));
        }
        (v, String::new())
    } else {
        // SAFETY: A NUL-terminated string.
        let host = String::from_utf8_lossy(unsafe { cstr(node) }).into_owned();
        match slate_resolve::literal(&host) {
            Some(a) => {
                if !(want == slate_resolve::Family::Any || (want == slate_resolve::Family::V6) == a.is_v6()) {
                    return EAI_FAMILY;
                }
                (alloc::vec![a], host)
            }
            None if flags & AI_NUMERICHOST != 0 => return EAI_NONAME,
            None => match slate_resolve::resolve(&host, want) {
                Ok(v) => (v, host),
                Err(slate_resolve::Error::NoSuchHost | slate_resolve::Error::NoAddress) => return EAI_NONAME,
                Err(slate_resolve::Error::NoAnswer) => return EAI_AGAIN,
                Err(_) => return EAI_FAIL,
            },
        }
    };
    let kinds: Vec<(c_int, c_int)> = match (socktype, protocol) {
        (0, 0) => alloc::vec![(SOCK_STREAM, IPPROTO_TCP), (SOCK_DGRAM, IPPROTO_UDP), (SOCK_RAW, 0)],
        (SOCK_STREAM, p) => alloc::vec![(SOCK_STREAM, if p == 0 { IPPROTO_TCP } else { p })],
        (SOCK_DGRAM, p) => alloc::vec![(SOCK_DGRAM, if p == 0 { IPPROTO_UDP } else { p })],
        (k, p) => alloc::vec![(k, p)],
    };
    let mut head: *mut AddrInfo = null_mut();
    let mut tail: *mut AddrInfo = null_mut();
    for a in &addrs {
        for &(kind, proto) in &kinds {
            let (storage, len, fam) = sockaddr(a, port);
            let e = Box::into_raw(Box::new(Entry {
                ai: AddrInfo {
                    flags,
                    family: fam,
                    socktype: kind,
                    protocol: proto,
                    addrlen: len,
                    addr: null_mut(),
                    canonname: null_mut(),
                    next: null_mut(),
                },
                storage,
                name: None,
            }));
            // SAFETY: A fresh entry; its storage stays put in the box.
            unsafe {
                (*e).ai.addr = (*e).storage.as_mut_ptr();
                if head.is_null() {
                    if flags & AI_CANONNAME != 0 {
                        let mut n = canon.clone().into_bytes();
                        n.push(0);
                        let b = n.into_boxed_slice();
                        (*e).ai.canonname = b.as_ptr() as *mut c_char;
                        (*e).name = Some(b);
                    }
                    head = e as *mut AddrInfo;
                } else {
                    (*tail).next = e as *mut AddrInfo;
                }
            }
            tail = e as *mut AddrInfo;
        }
    }
    if head.is_null() {
        return EAI_NONAME;
    }
    // SAFETY: C passes room for the list.
    unsafe { *res = head };
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn freeaddrinfo(mut ai: *mut AddrInfo) {
    while !ai.is_null() {
        // SAFETY: Each entry came from getaddrinfo's Box<Entry>.
        let e = unsafe { Box::from_raw(ai as *mut Entry) };
        ai = e.ai.next;
    }
}

static GAI_TEXT: [(c_int, &core::ffi::CStr); 9] = [
    (EAI_BADFLAGS, c"Bad value for ai_flags"),
    (EAI_NONAME, c"Name or service not known"),
    (EAI_AGAIN, c"Temporary failure in name resolution"),
    (EAI_FAIL, c"Non-recoverable failure in name resolution"),
    (EAI_FAMILY, c"Address family not supported"),
    (EAI_SOCKTYPE, c"Socket type not supported"),
    (EAI_SERVICE, c"Service not supported for socket type"),
    (EAI_SYSTEM, c"System error"),
    (EAI_OVERFLOW, c"Buffer too small"),
];

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn gai_strerror(e: c_int) -> *const c_char {
    GAI_TEXT.iter().find(|(n, _)| *n == e).map_or(c"Unknown error".as_ptr(), |(_, t)| t.as_ptr())
}

const NI_NAMEREQD: c_int = 8;

/// getnameinfo: numeric answers only (there are no reverse lookups).
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn getnameinfo(
    addr: *const u8,
    len: u32,
    host: *mut c_char,
    hostlen: u32,
    serv: *mut c_char,
    servlen: u32,
    flags: c_int,
) -> c_int {
    if flags & NI_NAMEREQD != 0 {
        return EAI_NONAME;
    }
    // SAFETY: C passes `len` bytes of address.
    let a = unsafe { core::slice::from_raw_parts(addr, len as usize) };
    if a.len() < 2 {
        return EAI_FAMILY;
    }
    let fam = c_int::from(u16::from_ne_bytes([a[0], a[1]]));
    let (text, port) = match fam {
        AF_INET if a.len() >= 16 => {
            (alloc::format!("{}", Ipv4([a[4], a[5], a[6], a[7]])), u16::from_be_bytes([a[2], a[3]]))
        }
        AF_INET6 if a.len() >= 24 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&a[8..24]);
            (alloc::format!("{}", Ipv6(b)), u16::from_be_bytes([a[2], a[3]]))
        }
        _ => return EAI_FAMILY,
    };
    let put = |dst: *mut c_char, room: u32, s: &str| -> bool {
        if dst.is_null() || room == 0 {
            return true;
        }
        if s.len() + 1 > room as usize {
            return false;
        }
        // SAFETY: `dst` holds `room` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), dst as *mut u8, s.len());
            *dst.add(s.len()) = 0;
        }
        true
    };
    if !put(host, hostlen, &text) || !put(serv, servlen, &alloc::format!("{port}")) {
        return EAI_OVERFLOW;
    }
    0
}

/// `struct hostent`, for gethostbyname.
#[repr(C)]
pub struct HostEnt {
    name: *mut c_char,
    aliases: *mut *mut c_char,
    addrtype: c_int,
    length: c_int,
    addr_list: *mut *mut c_char,
}

/// gethostbyname's static answer (POSIX lets it be overwritten).
struct HostBuf {
    ent: HostEnt,
    name: Vec<u8>,
    addrs: Vec<[u8; 4]>,
    ptrs: Vec<*mut c_char>,
    no_aliases: [*mut c_char; 1],
}

#[thread_local]
static HOST: core::cell::UnsafeCell<Option<HostBuf>> = core::cell::UnsafeCell::new(None);

/// h_errno's HOST_NOT_FOUND.
#[thread_local]
static H_ERRNO: core::cell::Cell<c_int> = core::cell::Cell::new(0);

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn __h_errno_location() -> *mut c_int {
    H_ERRNO.as_ptr()
}

/// gethostbyname: IPv4 addresses for a name (obsolete; getaddrinfo is the
/// interface to use).
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyname(name: *const c_char) -> *mut HostEnt {
    // SAFETY: C passes a NUL-terminated name.
    let host = String::from_utf8_lossy(unsafe { cstr(name) }).into_owned();
    let addrs: Vec<[u8; 4]> = match slate_resolve::resolve(&host, slate_resolve::Family::V4) {
        Ok(v) => v.iter().filter_map(|a| if let IpAddr::V4(x) = a { Some(x.0) } else { None }).collect(),
        Err(_) => Vec::new(),
    };
    if addrs.is_empty() {
        H_ERRNO.set(1);
        return null_mut();
    }
    // SAFETY: The calling thread's own buffer, rebuilt in place.
    let slot = unsafe { &mut *HOST.get() };
    let mut n = host.into_bytes();
    n.push(0);
    *slot = Some(HostBuf {
        ent: HostEnt { name: null_mut(), aliases: null_mut(), addrtype: AF_INET, length: 4, addr_list: null_mut() },
        name: n,
        addrs,
        ptrs: Vec::new(),
        no_aliases: [null_mut()],
    });
    let b = slot.as_mut().unwrap_or_else(|| unreachable!());
    b.ptrs = b.addrs.iter_mut().map(|a| a.as_mut_ptr() as *mut c_char).collect();
    b.ptrs.push(null_mut());
    b.ent.name = b.name.as_mut_ptr() as *mut c_char;
    b.ent.aliases = b.no_aliases.as_mut_ptr();
    b.ent.addr_list = b.ptrs.as_mut_ptr();
    &mut b.ent
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert_eq!(strict_v4("10.0.2.15"), Some([10, 0, 2, 15]));
        assert_eq!(strict_v4("10.0.2"), None);
        assert_eq!(strict_v4("010.0.0.1"), None);
        assert_eq!(strict_v4("256.0.0.1"), None);
        assert_eq!(aton(b"127.1"), Some(0x7f00_0001));
        assert_eq!(aton(b"0x7f.0.0.1"), Some(0x7f00_0001));
        assert_eq!(aton(b"10.0.0.0377"), Some(0x0a00_00ff));
        assert_eq!(aton(b"1.2.3.4.5"), None);
        assert_eq!(aton(b"300.1"), None);
        assert_eq!(service_port("443", true), Some(443));
        assert_eq!(service_port("ssh", true), None);
        assert_eq!(htons(0x1234), 0x3412);
    }
}
