// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate's network protocols, written from the RFCs (ADR 0017): Ethernet,
//! ARP, IPv4 and IPv6 (with forwarding and fragments), ICMP and ICMPv6
//! with neighbour discovery and stateless autoconfiguration, UDP, TCP and
//! DHCP, and packet sockets. `no_std` and free of I/O and clocks, so
//! the whole stack is unit-tested on the host by wiring stacks together.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod dhcp;
mod stack;
pub mod wire;

/// How nf_tables answers a socket's errors (its NETLINK_CAP_ACK and
/// NETLINK_EXT_ACK), for the kernel's netlink sockets.
pub use slate_nft::AckOpts;
/// SlateOS's default inbound firewall (ADR 0134), as batches.
pub use slate_nft::inbound;
pub use stack::{
    AddrOrigin, AddrState, Change, Config, ETH_P_ALL, Endpoint, Error, Handle, If6Addr, IfAddr, IfIndex, IfInfo,
    IpOptions, LOOPBACK, Lease, LinkAddr, Neighbour, ORIGIN_ICMP, ORIGIN_ICMP6, OptionField, PACKET_BROADCAST,
    PACKET_HOST, PACKET_MULTICAST, PACKET_OUTGOING, PROTO_BOOT, PROTO_DHCP, PROTO_KERNEL, PROTO_RA, PROTO_STATIC,
    QueuedError, RecvMeta, Result, Route, Route6, SocketEntry, Stack, TcpInfo, TcpOptions, TcpState, TcpStatus,
};
pub use wire::{IpAddr, Ipv4, Ipv6, Mac};

#[cfg(test)]
mod tcp_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests6;
