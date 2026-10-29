// SPDX-License-Identifier: MIT OR Apache-2.0

//! Interface ioctls on sockets (netdevice(7)): what ifconfig and friends
//! read. Request numbers from musl `bits/ioctl.h` (ADR 0009). Interfaces
//! are the namespace's stack's (lo is index 1, ADR 0048).

use alloc::string::String;

use slate_net::{Ipv4, Mac};

use crate::abi::linux::errno::*;
use crate::arch::uaccess::{copy_from_user, copy_to_user, read_user, write_user};
use crate::fs::vfs::Result;

const SIOCGIFNAME: u32 = 0x8910;
const SIOCGIFCONF: u32 = 0x8912;
const SIOCGIFFLAGS: u32 = 0x8913;
const SIOCSIFFLAGS: u32 = 0x8914;
const SIOCGIFADDR: u32 = 0x8915;
const SIOCGIFDSTADDR: u32 = 0x8917;
const SIOCGIFBRDADDR: u32 = 0x8919;
const SIOCGIFNETMASK: u32 = 0x891B;
const SIOCGIFMETRIC: u32 = 0x891D;
const SIOCGIFMTU: u32 = 0x8921;
const SIOCGIFHWADDR: u32 = 0x8927;
const SIOCGIFINDEX: u32 = 0x8933;
const SIOCGIFTXQLEN: u32 = 0x8942;

// Interface flags and hardware types (netdevice(7), arp(7)).
pub(super) const IFF_UP: u32 = 0x1;
const IFF_BROADCAST: u32 = 0x2;
pub(super) const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;
const IFF_MULTICAST: u32 = 0x1000;
const IFF_LOWER_UP: u32 = 0x10000;
const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;

/// `struct ifreq`: a 16-byte name, then a 24-byte union.
const IFREQ: usize = 40;

pub(super) struct Iface {
    pub name: String,
    pub index: i32,
    /// IFF_* (the low 16 bits fit `ifr_flags`; netlink also gets IFF_LOWER_UP).
    pub flags: u32,
    pub addrs: alloc::vec::Vec<slate_net::IfAddr>,
    pub addrs6: alloc::vec::Vec<slate_net::If6Addr>,
    pub mac: Mac,
    pub hw_type: u16,
    pub mtu: usize,
    /// IFLA_INFO_KIND (veth, bridge...; none for cards and loopback).
    pub kind: Option<&'static str>,
    /// The bridge it is a port of (0: none).
    pub master: u32,
    /// A veth end's peer's index, in the peer's namespace (0: none).
    pub peer: u32,
}

impl Iface {
    /// The first address and its netmask.
    pub fn addr(&self) -> Option<(Ipv4, Ipv4)> {
        self.addrs.first().map(|a| (a.addr, a.netmask()))
    }
}

pub(super) fn interfaces() -> alloc::vec::Vec<Iface> {
    interfaces_in(super::current_ns().id)
}

/// The interfaces of network namespace `ns`, in index order.
pub(super) fn interfaces_in(ns: u64) -> alloc::vec::Vec<Iface> {
    super::with_stack_in(ns, |st| st.interfaces()).into_iter().map(|i| iface(ns, &i)).collect()
}

pub(super) fn iface(ns: u64, i: &slate_net::IfInfo) -> Iface {
    let loopback = i.index == slate_net::LOOPBACK;
    let mut flags = if loopback { IFF_LOOPBACK } else { IFF_BROADCAST | IFF_MULTICAST };
    if i.up {
        flags |= IFF_UP;
        if i.carrier {
            flags |= IFF_RUNNING | IFF_LOWER_UP;
        }
    }
    let link = super::link::find(ns, i.index);
    Iface {
        kind: link.as_ref().and_then(|l| l.kind.name()),
        master: link.as_ref().map_or(0, |l| l.master()),
        peer: link.as_ref().and_then(|l| l.peer()).map_or(0, |p| p.index()),
        name: link.as_ref().map_or_else(|| super::name_of(ns, i.index).unwrap_or_default(), |l| l.name()),
        index: i.index as i32,
        flags,
        addrs: i.addrs.clone(),
        addrs6: i.addrs6.clone(),
        mac: i.mac,
        hw_type: if loopback { ARPHRD_LOOPBACK } else { ARPHRD_ETHER },
        mtu: i.mtu,
    }
}

fn sockaddr(ip: Ipv4) -> [u8; 16] {
    super::socket::sockaddr_in((ip, 0))
}

pub fn interface_ioctl(cmd: u32, arg: u64) -> Result<u64> {
    if cmd == SIOCGIFCONF {
        // struct ifconf { int ifc_len; (pad) char *ifc_buf; }
        let len: i32 = read_user(arg).map_err(|_| EFAULT)?;
        let buf: u64 = read_user(arg + 8).map_err(|_| EFAULT)?;
        let mut written = 0usize;
        for i in interfaces() {
            let Some((ip, _)) = i.addr() else { continue };
            if buf != 0 && written + IFREQ <= len as usize {
                let mut r = [0u8; IFREQ];
                r[..i.name.len()].copy_from_slice(i.name.as_bytes());
                r[16..32].copy_from_slice(&sockaddr(ip));
                copy_to_user(buf + written as u64, &r).map_err(|_| EFAULT)?;
            }
            written += IFREQ;
        }
        if buf != 0 {
            written = written.min(len as usize / IFREQ * IFREQ);
        }
        write_user(arg, &(written as i32)).map_err(|_| EFAULT)?;
        return Ok(0);
    }
    let mut req = [0u8; IFREQ];
    let known = matches!(
        cmd,
        SIOCGIFNAME
            | SIOCGIFFLAGS
            | SIOCSIFFLAGS
            | SIOCGIFADDR
            | SIOCGIFDSTADDR
            | SIOCGIFBRDADDR
            | SIOCGIFNETMASK
            | SIOCGIFMETRIC
            | SIOCGIFMTU
            | SIOCGIFHWADDR
            | SIOCGIFINDEX
            | SIOCGIFTXQLEN
    );
    if !known {
        return Err(ENOTTY);
    }
    copy_from_user(&mut req, arg).map_err(|_| EFAULT)?;
    let all = interfaces();
    let iface = if cmd == SIOCGIFNAME {
        let index = i32::from_ne_bytes(req[16..20].try_into().unwrap());
        all.into_iter().find(|i| i.index == index).ok_or(ENODEV)?
    } else {
        let end = req[..16].iter().position(|&b| b == 0).unwrap_or(16);
        let name = core::str::from_utf8(&req[..end]).map_err(|_| ENODEV)?;
        all.into_iter().find(|i| i.name == name).ok_or(ENODEV)?
    };
    let u = &mut req[16..];
    match cmd {
        SIOCGIFNAME => {
            req[..16].fill(0);
            req[..iface.name.len()].copy_from_slice(iface.name.as_bytes());
        }
        SIOCGIFFLAGS => u[..2].copy_from_slice(&(iface.flags as u16).to_ne_bytes()),
        SIOCSIFFLAGS => {
            let ns = super::current_ns();
            if !crate::proc::cred::current().ns_capable(&ns.owner, crate::proc::cred::CAP_NET_ADMIN) {
                return Err(EPERM);
            }
            let flags = u16::from_ne_bytes([u[0], u[1]]);
            super::set_up(ns.id, iface.index as u32, u32::from(flags) & IFF_UP != 0).map_err(super::socket::errno)?;
            return Ok(0);
        }
        SIOCGIFADDR | SIOCGIFDSTADDR => u[..16].copy_from_slice(&sockaddr(iface.addr().ok_or(EADDRNOTAVAIL)?.0)),
        SIOCGIFNETMASK => {
            let (_, mask) = iface.addr().ok_or(EADDRNOTAVAIL)?;
            u[..16].copy_from_slice(&sockaddr(mask));
        }
        SIOCGIFBRDADDR => {
            let (ip, mask) = iface.addr().ok_or(EADDRNOTAVAIL)?;
            u[..16].copy_from_slice(&sockaddr(Ipv4::from_u32(ip.to_u32() | !mask.to_u32())));
        }
        SIOCGIFMETRIC => u[..4].fill(0),
        SIOCGIFMTU => u[..4].copy_from_slice(&(iface.mtu as i32).to_ne_bytes()),
        SIOCGIFTXQLEN => u[..4].copy_from_slice(&1000i32.to_ne_bytes()),
        SIOCGIFINDEX => u[..4].copy_from_slice(&iface.index.to_ne_bytes()),
        SIOCGIFHWADDR => {
            u[..2].copy_from_slice(&iface.hw_type.to_ne_bytes());
            u[2..8].copy_from_slice(&iface.mac.0);
        }
        _ => unreachable!(),
    }
    copy_to_user(arg, &req).map_err(|_| EFAULT)?;
    Ok(0)
}
