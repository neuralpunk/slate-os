// SPDX-License-Identifier: MIT OR Apache-2.0

//! /proc (proc(5)): process and kernel information as text files.
//!
//! Directory contents are computed on lookup; file contents are generated
//! when the file is opened, so a reader sees one consistent snapshot. The
//! formats are those proc(5) documents, as far as real tools need them.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt::Write;
use core::sync::atomic::Ordering;

use super::File;
use super::vfs::*;
use crate::abi::linux::errno::*;
use crate::proc::{self, Pid};
use crate::sync::IrqSpinLock;

/// Device number reported for /proc.
const PROC_DEV: u64 = 0xF0;

fn meta(ino: Ino, mode: u32) -> Metadata {
    let now = Timespec::now();
    Metadata {
        dev: PROC_DEV,
        ino,
        mode,
        nlink: if mode & S_IFMT == S_IFDIR { 2 } else { 1 },
        atime: now,
        mtime: now,
        ctime: now,
        ..Default::default()
    }
}

/// What a /proc node is.
#[derive(Clone, Debug)]
enum Node {
    Root,
    SelfLink,
    /// /proc/thread-self: `<pid>/task/<tid>` of the reading thread.
    ThreadSelf,
    Global(&'static str),
    PidDir(Pid),
    /// /proc/<pid>/task and /proc/<pid>/task/<tid> (a host thread ID); a
    /// thread's directory shows its process's files, but for
    /// [`THREAD_FILES`], which are the thread's own.
    TaskDir(Pid),
    Task(Pid, u64),
    PidFile(Pid, &'static str),
    ThreadFile(Pid, u64, &'static str),
    PidLink(Pid, &'static str),
    /// /proc/<pid>/ns (thread 0: the main thread's) or a task's.
    NsDir(Pid, u64),
    NsLink(Pid, u64, &'static str),
    FdDir(Pid),
    FdLink(Pid, i32),
    /// /proc/<pid>/fdinfo and its files (proc(5): pos, flags, mnt_id).
    FdInfoDir(Pid),
    FdInfo(Pid, i32),
    NetDir,
    NetFile(&'static str),
    /// /proc/sys: a path from SYS_TREE ("sys/kernel/hostname").
    Sys(&'static str),
    /// /proc/asound and what is in it ("", "cards", "card0/pcm0p/info"),
    /// from the sound core (ADR 0184).
    Asound(String),
    /// /proc/sys/net/ipv4/conf/DEV and ipv6/conf/DEV (`all`, `default`, or
    /// an interface of the reader's network namespace), and their files.
    NetConf {
        v6: bool,
        dev: String,
        key: Option<&'static str>,
    },
}

/// /proc/sys (proc(5)): directories end in '/'. The values are Slate's
/// fixed limits, the reader's namespaces, or what was written: net values
/// per network namespace, hostname and domainname to the UTS namespace,
/// the rest globally (stored, mostly without effect: docs/GAPS.md).
const SYS_TREE: &[&str] = &[
    "sys/",
    "sys/fs/",
    "sys/fs/binfmt_misc/",
    "sys/fs/file-max",
    "sys/fs/nr_open",
    "sys/fs/protected_fifos",
    "sys/fs/protected_hardlinks",
    "sys/fs/protected_regular",
    "sys/fs/protected_symlinks",
    "sys/kernel/",
    "sys/kernel/cap_last_cap",
    "sys/kernel/domainname",
    "sys/kernel/hostname",
    "sys/kernel/ngroups_max",
    "sys/kernel/osrelease",
    "sys/kernel/ostype",
    "sys/kernel/overflowgid",
    "sys/kernel/overflowuid",
    "sys/kernel/pid_max",
    "sys/kernel/random/",
    "sys/kernel/random/boot_id",
    "sys/kernel/random/uuid",
    "sys/kernel/randomize_va_space",
    "sys/kernel/tainted",
    "sys/kernel/threads-max",
    "sys/net/",
    "sys/net/ipv4/",
    "sys/net/ipv4/conf/",
    "sys/net/ipv4/ip_forward",
    "sys/net/ipv4/ip_local_port_range",
    "sys/net/ipv4/ip_unprivileged_port_start",
    "sys/net/ipv4/ping_group_range",
    "sys/net/ipv6/",
    "sys/net/ipv6/conf/",
    "sys/slate/",
    "sys/slate/devmode",
    "sys/slate/keyboard",
    "sys/slate/linux_compat",
    "sys/slate/linux_release",
    "sys/user/",
    "sys/user/max_user_namespaces",
    "sys/vm/",
    "sys/vm/drop_caches",
    "sys/vm/max_map_count",
    "sys/vm/overcommit_memory",
    "sys/vm/overcommit_ratio",
];

/// The SYS_TREE entry for `path` (a directory or a file).
fn sys_entry(path: &str) -> Option<&'static str> {
    SYS_TREE.iter().copied().find(|e| e.trim_end_matches('/') == path)
}

/// A random UUID in the usual text form (random(4), /proc/sys/kernel/random).
fn uuid_text(b: [u8; 16]) -> String {
    let mut b = b;
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    let h: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}\n",
        h[..4].concat(),
        h[4..6].concat(),
        h[6..8].concat(),
        h[8..10].concat(),
        h[10..].concat()
    )
}

/// Changed /proc/sys values outside the per-namespace ones.
static SYSCTL: IrqSpinLock<alloc::collections::BTreeMap<&'static str, String>> =
    IrqSpinLock::new(alloc::collections::BTreeMap::new());

/// Files under /proc/sys that can be written.
fn sys_writable(path: &str) -> bool {
    matches!(
        path,
        "sys/kernel/domainname"
            | "sys/kernel/hostname"
            | "sys/kernel/pid_max"
            | "sys/kernel/randomize_va_space"
            | "sys/kernel/threads-max"
            | "sys/fs/file-max"
            | "sys/fs/protected_fifos"
            | "sys/fs/protected_hardlinks"
            | "sys/fs/protected_regular"
            | "sys/fs/protected_symlinks"
            | "sys/net/ipv4/ip_forward"
            | "sys/net/ipv4/ip_unprivileged_port_start"
            | "sys/net/ipv4/ping_group_range"
            | "sys/user/max_user_namespaces"
            | "sys/vm/drop_caches"
            | "sys/vm/max_map_count"
            | "sys/vm/overcommit_memory"
            | "sys/vm/overcommit_ratio"
            | "sys/slate/linux_compat"
            | "sys/slate/devmode"
            | "sys/slate/keyboard"
    )
}

/// ping_group_range's default: every group may open ping sockets (ADR
/// 0052; icmp(7) documents Linux's "1 0", no group).
pub const PING_GROUPS: &str = "0\t2147483647";

/// A /proc/sys value as written, or `default` (the calling process's
/// network namespace for net values).
pub fn sysctl(path: &'static str, default: &str) -> String {
    let set = if path.starts_with("sys/net/") {
        crate::net::current_ns().sysctl.lock().get(path).cloned()
    } else {
        SYSCTL.lock().get(path).cloned()
    };
    set.unwrap_or_else(|| default.into())
}

/// Write a /proc/sys file: one value (numbers, or two for
/// ping_group_range), checked, with the capability over the namespace it
/// belongs to.
fn write_sys_file(path: &'static str, buf: &[u8]) -> Result<usize> {
    use crate::proc::cred::{CAP_NET_ADMIN, CAP_SYS_ADMIN};
    let text = written_text(buf)?.trim_end_matches('\n');
    let cred = crate::proc::cred::current();
    let p = proc::current().ok_or(ESRCH)?;
    // Linux compatibility mode (ADR 0032): root in the Slate domain only.
    if path == "sys/slate/linux_compat" {
        if cred.euid != 0 || p.domain() != crate::proc::domain::Domain::Slate {
            return Err(EPERM);
        }
        match text {
            "0" => crate::proc::domain::set_compat(false),
            "1" => crate::proc::domain::set_compat(true),
            _ => return Err(EINVAL),
        }
        return Ok(buf.len());
    }
    // Developer mode (ADR 0090): it only goes off, by root in the Slate
    // domain; on comes from the kernel command line alone.
    if path == "sys/slate/devmode" {
        if cred.euid != 0 || p.domain() != crate::proc::domain::Domain::Slate {
            return Err(EPERM);
        }
        match text {
            "0" => crate::proc::domain::end_devmode(),
            "1" if crate::proc::domain::devmode() => {}
            "1" => return Err(EPERM),
            _ => return Err(EINVAL),
        }
        return Ok(buf.len());
    }
    // Address space layout randomization (ADR 0092): it weakens every
    // process, so root in the Slate domain only.
    if path == "sys/kernel/randomize_va_space" {
        if cred.euid != 0 || p.domain() != crate::proc::domain::Domain::Slate {
            return Err(EPERM);
        }
        match text {
            "0" | "1" | "2" => crate::proc::aslr::set_level(text.as_bytes()[0] - b'0'),
            _ => return Err(EINVAL),
        }
        return Ok(buf.len());
    }
    // The console's keyboard layout (ADR 0039): root only.
    if path == "sys/slate/keyboard" {
        if cred.euid != 0 {
            return Err(EPERM);
        }
        let layout = slate_term::keymap::Layout::by_name(text).ok_or(EINVAL)?;
        crate::drivers::input::set_layout(layout);
        return Ok(buf.len());
    }
    // Per user namespace (ADR 0114): its owner, or whoever holds
    // CAP_SYS_RESOURCE over it, sets how many may live below it.
    if path == "sys/user/max_user_namespaces" {
        if !cred.ns_capable(&cred.user_ns, crate::proc::cred::CAP_SYS_RESOURCE) {
            return Err(EPERM);
        }
        let v: u64 = text.trim().parse().map_err(|_| EINVAL)?;
        if v > i32::MAX as u64 {
            return Err(EINVAL);
        }
        cred.user_ns.max_user_ns.store(v, Ordering::Relaxed);
        return Ok(buf.len());
    }
    // The link restrictions (proc(5)): root of the initial user namespace.
    if let Some((setting, max)) = path.strip_prefix("sys/fs/").and_then(super::protect::setting) {
        if !cred.capable(CAP_SYS_ADMIN) {
            return Err(EPERM);
        }
        let v: u8 = text.trim().parse().map_err(|_| EINVAL)?;
        if v > max {
            return Err(EINVAL);
        }
        setting.store(v, Ordering::Relaxed);
        return Ok(buf.len());
    }
    // Dropping clean caches (proc(5)): 1 the page cache, 2 the dentries
    // nothing uses and the misses, 3 both; 4 only stops the message.
    if path == "sys/vm/drop_caches" {
        if !cred.capable(CAP_SYS_ADMIN) {
            return Err(EPERM);
        }
        let v: u8 = text.trim().parse().map_err(|_| EINVAL)?;
        if !(1..=4).contains(&v) {
            return Err(EINVAL);
        }
        if v & 2 != 0 {
            let (dentries, misses) = super::vfs::dcache::drop_all();
            crate::log_info!("drop_caches: {dentries} dentries and {misses} misses dropped");
        }
        if v & 1 != 0 {
            let pages = super::pagecache::drop_clean();
            crate::log_info!("drop_caches: {pages} cached pages dropped");
        }
        return Ok(buf.len());
    }
    // The overcommit policy (ADR 0123): root of the initial namespace.
    if path == "sys/vm/overcommit_memory" || path == "sys/vm/overcommit_ratio" {
        if !cred.capable(CAP_SYS_ADMIN) {
            return Err(EPERM);
        }
        let v: u64 = text.trim().parse().map_err(|_| EINVAL)?;
        if path.ends_with("memory") {
            if v > 2 {
                return Err(EINVAL);
            }
            crate::mm::commit::MODE.store(v as u8, Ordering::Relaxed);
        } else {
            crate::mm::commit::RATIO.store(v, Ordering::Relaxed);
        }
        return Ok(buf.len());
    }
    let n = p.namespaces();
    if path == "sys/kernel/hostname" || path == "sys/kernel/domainname" {
        if !cred.ns_capable(&n.uts.owner, CAP_SYS_ADMIN) {
            return Err(EPERM);
        }
        if text.len() > 64 {
            return Err(EINVAL);
        }
        let slot = if path == "sys/kernel/hostname" { &n.uts.hostname } else { &n.uts.domainname };
        *slot.lock() = text.as_bytes().to_vec();
        return Ok(buf.len());
    }
    let nums: Vec<i64> = text
        .split_whitespace()
        .map(|x| x.parse::<i64>())
        .collect::<core::result::Result<_, _>>()
        .map_err(|_| EINVAL)?;
    let want = if path == "sys/net/ipv4/ping_group_range" { 2 } else { 1 };
    if nums.len() != want || nums.iter().any(|v| *v < 0 || *v > i64::from(u32::MAX)) {
        return Err(EINVAL);
    }
    let value = nums.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\t");
    if path.starts_with("sys/net/") {
        if !cred.ns_capable(&n.net.owner, CAP_NET_ADMIN) {
            return Err(EPERM);
        }
        // ip_forward turns the stack's forwarding on or off (ADR 0049).
        if path == "sys/net/ipv4/ip_forward" {
            if nums[0] > 1 {
                return Err(EINVAL);
            }
            crate::net::with_stack_in(n.net.id, |st| st.set_forwarding(nums[0] == 1));
        }
        n.net.sysctl.lock().insert(path.into(), value);
    } else {
        if !cred.capable(CAP_SYS_ADMIN) {
            return Err(EPERM);
        }
        SYSCTL.lock().insert(path, value);
    }
    Ok(buf.len())
}

/// The settings an interface has under /proc/sys/net/ipv4/conf/DEV and
/// ipv6/conf/DEV (ip-sysctl in the kernel's documentation, as `sysctl -a`
/// shows them on the host), with Linux's defaults. Forwarding acts (`all`
/// is ip_forward, and IPv6's forwarding switch); the rest are kept for the
/// programs that set them (Docker, NetworkManager) and do nothing
/// (docs/GAPS.md).
fn conf_keys(v6: bool) -> &'static [(&'static str, &'static str)] {
    if v6 {
        &[
            ("accept_dad", "1"),
            ("accept_ra", "1"),
            ("accept_redirects", "1"),
            ("autoconf", "1"),
            ("disable_ipv6", "0"),
            ("forwarding", "0"),
            ("hop_limit", "64"),
            ("keep_addr_on_down", "0"),
            ("use_tempaddr", "0"),
        ]
    } else {
        &[
            ("accept_local", "0"),
            ("accept_redirects", "1"),
            ("accept_source_route", "0"),
            ("arp_announce", "0"),
            ("arp_ignore", "0"),
            ("disable_policy", "0"),
            ("forwarding", "0"),
            ("promote_secondaries", "0"),
            ("proxy_arp", "0"),
            ("route_localnet", "0"),
            ("rp_filter", "0"),
            ("send_redirects", "1"),
        ]
    }
}

/// `all`, `default` and the reader's namespace's interfaces.
fn conf_devices() -> Vec<String> {
    let ns = crate::net::current_ns().id;
    let mut out = alloc::vec![String::from("all"), String::from("default")];
    out.extend(
        crate::net::with_stack_in(ns, |st| st.interfaces())
            .into_iter()
            .filter_map(|i| crate::net::name_of(ns, i.index)),
    );
    out
}

fn conf_path(v6: bool, dev: &str, key: &str) -> String {
    format!("sys/net/ipv{}/conf/{dev}/{key}", if v6 { 6 } else { 4 })
}

/// An interface's setting: its own, else `default`'s, else Linux's
/// default; IPv4's `all/forwarding` is ip_forward.
fn conf_value(v6: bool, dev: &str, key: &str) -> String {
    if !v6 && dev == "all" && key == "forwarding" {
        return sysctl("sys/net/ipv4/ip_forward", "0");
    }
    let ns = crate::net::current_ns();
    let set = ns.sysctl.lock();
    let own = set.get(&conf_path(v6, dev, key)).cloned();
    let default = || if dev == "all" { None } else { set.get(&conf_path(v6, "default", key)).cloned() };
    own.or_else(default)
        .unwrap_or_else(|| conf_keys(v6).iter().find(|k| k.0 == key).map_or_else(String::new, |k| k.1.into()))
}

/// Write an interface's setting: a number, CAP_NET_ADMIN over the
/// network namespace. `all/forwarding` turns forwarding on or off.
fn write_conf(v6: bool, dev: &str, key: &str, buf: &[u8]) -> Result<usize> {
    let text = written_text(buf)?.trim();
    let v: i64 = text.parse().map_err(|_| EINVAL)?;
    let ns = crate::net::current_ns();
    if !crate::proc::cred::current().ns_capable(&ns.owner, crate::proc::cred::CAP_NET_ADMIN) {
        return Err(EPERM);
    }
    if dev != "all" && dev != "default" && crate::net::index_of(ns.id, dev).is_none() {
        return Err(ENODEV);
    }
    if key == "forwarding" && dev == "all" {
        if !(0..=1).contains(&v) {
            return Err(EINVAL);
        }
        if v6 {
            crate::net::with_stack_in(ns.id, |st| st.set_forwarding6(v == 1));
        } else {
            crate::net::with_stack_in(ns.id, |st| st.set_forwarding(v == 1));
            ns.sysctl.lock().insert("sys/net/ipv4/ip_forward".into(), v.to_string());
        }
    }
    ns.sysctl.lock().insert(conf_path(v6, dev, key), v.to_string());
    Ok(buf.len())
}

fn sys_file(path: &'static str, s: &mut String) {
    let n = proc::current().map(|p| p.namespaces());
    let text = |v: &[u8]| String::from_utf8_lossy(v).into_owned();
    if let Some((setting, _)) = path.strip_prefix("sys/fs/").and_then(super::protect::setting) {
        let _ = writeln!(s, "{}", setting.load(Ordering::Relaxed));
        return;
    }
    let v = match path {
        "sys/fs/file-max" => sysctl(path, "9223372036854775807"),
        "sys/fs/nr_open" => crate::proc::rlimit::NR_OPEN.to_string(),
        // Never tainted: Slate loads no foreign modules (proc_sys_kernel(5)).
        "sys/kernel/tainted" => "0".to_string(),
        "sys/kernel/cap_last_cap" => crate::proc::cred::CAP_LAST.to_string(),
        "sys/kernel/domainname" => n.map_or_else(String::new, |n| text(&n.uts.domainname.lock())),
        "sys/kernel/hostname" => {
            let h = n.map_or_else(String::new, |n| text(&n.uts.hostname.lock()));
            if h.is_empty() { "slate".into() } else { h }
        }
        "sys/kernel/ngroups_max" => crate::proc::cred::NGROUPS_MAX.to_string(),
        // As uname tells the reader (ADR 0153).
        "sys/kernel/osrelease" => crate::abi::linux::process::identity().1.into(),
        "sys/kernel/ostype" => crate::abi::linux::process::identity().0.into(),
        "sys/slate/linux_release" => crate::abi::linux::process::LINUX_RELEASE.into(),
        "sys/slate/linux_compat" => if crate::proc::domain::compat() { "1" } else { "0" }.into(),
        "sys/slate/devmode" => if crate::proc::domain::devmode() { "1" } else { "0" }.into(),
        "sys/kernel/randomize_va_space" => crate::proc::aslr::level().to_string(),
        "sys/slate/keyboard" => crate::drivers::input::layout().name().into(),
        "sys/kernel/overflowgid" | "sys/kernel/overflowuid" => crate::proc::cred::OVERFLOW_ID.to_string(),
        "sys/kernel/pid_max" | "sys/kernel/threads-max" => sysctl(path, "4194304"),
        "sys/kernel/random/boot_id" => {
            static BOOT_ID: slate_sync::Once<[u8; 16]> = slate_sync::Once::new();
            let id = *BOOT_ID.call_once(|| {
                let mut b = [0u8; 16];
                crate::random::fill(&mut b);
                b
            });
            s.push_str(&uuid_text(id));
            return;
        }
        "sys/kernel/random/uuid" => {
            let mut b = [0u8; 16];
            crate::random::fill(&mut b);
            s.push_str(&uuid_text(b));
            return;
        }
        "sys/net/ipv4/ip_forward" => sysctl(path, "0"),
        // The stack's ephemeral range (libs/net), read-only.
        "sys/net/ipv4/ip_local_port_range" => "49152\t65535".into(),
        "sys/net/ipv4/ip_unprivileged_port_start" => sysctl(path, "1024"),
        "sys/net/ipv4/ping_group_range" => sysctl(path, PING_GROUPS),
        "sys/user/max_user_namespaces" => {
            crate::proc::cred::current().user_ns.max_user_ns.load(Ordering::Relaxed).to_string()
        }
        "sys/vm/drop_caches" => String::from("0"),
        "sys/vm/max_map_count" => sysctl(path, "65530"),
        "sys/vm/overcommit_memory" => crate::mm::commit::MODE.load(Ordering::Relaxed).to_string(),
        "sys/vm/overcommit_ratio" => crate::mm::commit::RATIO.load(Ordering::Relaxed).to_string(),
        _ => return,
    };
    let _ = writeln!(s, "{v}");
}

const GLOBAL_FILES: &[&str] = &[
    "cmdline",
    "cpuinfo",
    "diskstats",
    "filesystems",
    "interrupts",
    "loadavg",
    "locks",
    "meminfo",
    "mounts",
    "partitions",
    "slate_boot",
    "slate_drivers",
    "slate_kernel",
    "slate_profile",
    "slate_sched",
    "slate_strace",
    "stat",
    "uptime",
    "version",
];
/// The kernel's own file on the live system (`boot::kernel_file`): root
/// only, and there only.
const KERNEL_FILE: &str = "slate_kernel";

/// Whether global file `name` exists here.
fn global_present(name: &str) -> bool {
    name != KERNEL_FILE || crate::boot::kernel_file().is_some()
}

/// Slate's system call tracer control (abi/linux/trace.rs), writable by root.
const STRACE_FILE: &str = "slate_strace";
/// Slate's sampling profiler (proc/profile.rs): root only.
const PROFILE_FILE: &str = "slate_profile";
const PID_FILES: &[&str] = &[
    "cgroup",
    "cmdline",
    "comm",
    "environ",
    "gid_map",
    "io",
    "maps",
    "limits",
    "mountinfo",
    "mounts",
    "oom_score",
    "oom_score_adj",
    "setgroups",
    "stat",
    "statm",
    "status",
    "uid_map",
    "wchan",
];
/// Pid files that can be written.
const PID_WRITABLE: &[&str] = &["gid_map", "oom_score_adj", "setgroups", "uid_map"];
const PID_LINKS: &[&str] = &["cwd", "exe", "root"];
/// /proc/net: `pnp` (DHCP results, resolv.conf syntax, as Linux's kernel
/// autoconfiguration writes it), `dev` and `route` (for ifconfig/route),
/// `arp` (the ARP table, for arp(8)).
const NET_FILES: &[&str] = &["arp", "dev", "if_inet6", "ipv6_route", "pnp", "route", "tcp", "tcp6", "udp", "udp6"];

struct ProcInode {
    node: Node,
    /// The PID namespace of the process that mounted this procfs: PIDs
    /// are shown as it sees them (pid_namespaces(7)).
    ns: Arc<proc::ns::PidNs>,
}

pub fn new() -> Arc<dyn Inode> {
    Arc::new(ProcInode { node: Node::Root, ns: proc::caller_pid_ns() })
}

impl ProcInode {
    fn inode(&self, node: Node) -> Arc<dyn Inode> {
        Arc::new(ProcInode { node, ns: self.ns.clone() })
    }

    /// Host PID `pid` as this procfs shows it.
    fn local(&self, pid: Pid) -> Option<Pid> {
        if self.ns.level == 0 { Some(pid) } else { proc::get(pid).and_then(|p| p.pid_in(&self.ns)) }
    }
}

fn ino_of(node: &Node) -> Ino {
    let name_hash = |s: &str| s.bytes().fold(7u64, |h, b| h.wrapping_mul(31).wrapping_add(u64::from(b))) & 0xFFFF;
    match node {
        Node::Root => 1,
        Node::SelfLink => 2,
        Node::ThreadSelf => 4,
        Node::Global(n) => 0x100 + name_hash(n),
        Node::PidDir(p) => u64::from(*p) << 20,
        Node::TaskDir(p) => (u64::from(*p) << 20) | 0x5,
        Node::Task(p, t) => (u64::from(*p) << 20) | 0x20_0000 | (*t & 0xF_FFFF),
        Node::PidFile(p, n) | Node::PidLink(p, n) => (u64::from(*p) << 20) | 0x10_0000 | name_hash(n),
        Node::ThreadFile(p, t, n) => (u64::from(*p) << 20) | 0x80_0000 | ((*t & 0xFFF) << 8) ^ name_hash(n),
        Node::FdDir(p) => (u64::from(*p) << 20) | 0x2,
        Node::NsDir(p, t) => (u64::from(*p) << 20) | 0x3 | ((*t & 0xFFF) << 8),
        Node::NsLink(p, t, n) => (u64::from(*p) << 20) | 0x4_0000 | name_hash(n) ^ ((*t & 0xFF) << 16),
        Node::FdLink(p, fd) => (u64::from(*p) << 20) | 0x8_0000 | *fd as u64,
        Node::FdInfoDir(p) => (u64::from(*p) << 20) | 0x6,
        Node::FdInfo(p, fd) => (u64::from(*p) << 20) | 0x40_0000 | (*fd as u64 & 0xF_FFFF),
        Node::NetDir => 3,
        Node::NetFile(n) => 0x1_0000 + name_hash(n),
        Node::Sys(p) => 0x2_0000 + name_hash(p),
        Node::Asound(p) => 0x4_0000_0000 + name_hash(p),
        Node::NetConf { v6, dev, key } => {
            0x3_0000_0000 + (u64::from(*v6) << 40) + (name_hash(dev) << 8) + key.map_or(0, name_hash)
        }
    }
}

/// The namespaces of thread `tid` of `p` (0: its main thread).
fn thread_ns(p: &proc::Process, tid: u64) -> proc::ns::Namespaces {
    p.thread_namespaces(if tid == 0 { u64::from(p.pid) } else { tid })
}

/// The process behind a /proc/<pid> node, if the reader may see it
/// (ADR 0032: Linux-domain readers do not see Slate-domain processes).
fn process(pid: Pid) -> Result<Arc<proc::Process>> {
    proc::get(pid).filter(|p| proc::domain::may_inspect(p)).ok_or(ENOENT)
}

/// [`process`], for what only a process that may read it with ptrace
/// sees (proc(5): environ, maps, fd, fdinfo, cwd, exe, root, ns); EACCES
/// otherwise.
fn private(pid: Pid) -> Result<Arc<proc::Process>> {
    let p = process(pid)?;
    if crate::proc::cred::ptrace_may_read(&p) { Ok(p) } else { Err(EACCES) }
}

impl Inode for ProcInode {
    fn statfs(&self) -> Option<StatFs> {
        // PROC_SUPER_MAGIC (statfs(2)).
        Some(StatFs {
            magic: 0x9fa0,
            block_size: 4096,
            blocks: 0,
            free_blocks: 0,
            files: 0,
            free_files: 0,
            read_only: false,
        })
    }
    fn metadata(&self) -> Metadata {
        let ino = ino_of(&self.node);
        let mut m = match &self.node {
            Node::Root | Node::PidDir(_) | Node::NetDir | Node::TaskDir(_) | Node::Task(..) => {
                meta(ino, S_IFDIR | 0o555)
            }
            Node::Sys(p) if p.ends_with('/') => meta(ino, S_IFDIR | 0o555),
            Node::Asound(p) => match crate::drivers::sound::proc_entry(p) {
                Some(crate::drivers::sound::ProcEntry::Dir(_)) => meta(ino, S_IFDIR | 0o555),
                _ => meta(ino, S_IFREG | 0o444),
            },
            Node::NetConf { key: None, .. } => meta(ino, S_IFDIR | 0o555),
            Node::NetConf { .. } => meta(ino, S_IFREG | 0o644),
            Node::FdDir(_) => meta(ino, S_IFDIR | 0o500),
            Node::FdInfoDir(_) => meta(ino, S_IFDIR | 0o500),
            Node::FdInfo(..) => meta(ino, S_IFREG | 0o400),
            Node::NsDir(..) => meta(ino, S_IFDIR | 0o511),
            Node::SelfLink | Node::ThreadSelf | Node::PidLink(..) | Node::FdLink(..) | Node::NsLink(..) => {
                meta(ino, S_IFLNK | 0o777)
            }
            Node::PidFile(_, f) if PID_WRITABLE.contains(f) || *f == "comm" => meta(ino, S_IFREG | 0o644),
            Node::ThreadFile(_, _, "comm") => meta(ino, S_IFREG | 0o644),
            Node::PidFile(_, "environ") => meta(ino, S_IFREG | 0o400),
            Node::Global(STRACE_FILE) => meta(ino, S_IFREG | 0o644),
            Node::Global(PROFILE_FILE) => meta(ino, S_IFREG | 0o600),
            Node::Global(KERNEL_FILE) => {
                let mut m = meta(ino, S_IFREG | 0o400);
                m.size = crate::boot::kernel_file().map_or(0, |f| f.len() as u64);
                m
            }
            Node::Sys("sys/vm/drop_caches") => meta(ino, S_IFREG | 0o200),
            Node::Sys(p) if sys_writable(p) => meta(ino, S_IFREG | 0o644),
            Node::Global(_) | Node::PidFile(..) | Node::ThreadFile(..) | Node::NetFile(_) | Node::Sys(_) => {
                meta(ino, S_IFREG | 0o444)
            }
        };
        // A user namespace's own limit may be set by whoever holds
        // CAP_SYS_RESOURCE over it (the write checks it), so it is
        // writable to them whatever their IDs: bubblewrap's
        // --disable-userns writes it in the namespace it made, as the
        // person's own ID (observed: flatpak's sandboxes on Linux).
        if matches!(&self.node, Node::Sys(p) if *p == "sys/user/max_user_namespaces") {
            let cred = crate::proc::cred::current();
            let mode = if cred.ns_capable(&cred.user_ns, crate::proc::cred::CAP_SYS_RESOURCE) { 0o666 } else { 0o444 };
            m.mode = S_IFREG | mode;
        }
        // A process's entries belong to its effective user (proc(5)).
        if let Node::PidDir(p)
        | Node::PidFile(p, _)
        | Node::ThreadFile(p, _, _)
        | Node::PidLink(p, _)
        | Node::FdDir(p)
        | Node::FdLink(p, _)
        | Node::FdInfoDir(p)
        | Node::FdInfo(p, _)
        | Node::TaskDir(p)
        | Node::Task(p, _) = &self.node
            && let Some(pr) = proc::get(*p)
        {
            let c = pr.cred();
            (m.uid, m.gid) = (c.euid, c.egid);
        }
        // A network namespace's sysctls belong to the root of the user
        // namespace that owns it.
        if matches!(&self.node, Node::Sys(p) if p.starts_with("sys/net/")) || matches!(self.node, Node::NetConf { .. })
        {
            let owner = crate::net::current_ns().owner.clone();
            m.uid = owner.uid_to_kernel(0).unwrap_or(0);
            m.gid = owner.gid_to_kernel(0).unwrap_or(0);
        }
        // So does the user namespace's own limit (ADR 0114: as on Linux,
        // root inside the namespace opens it for writing).
        if let Node::Sys("sys/user/max_user_namespaces") = &self.node {
            let ns = crate::proc::cred::current().user_ns.clone();
            m.uid = ns.uid_to_kernel(0).unwrap_or(0);
            m.gid = ns.gid_to_kernel(0).unwrap_or(0);
        }
        m
    }

    fn uncached_child(&self, name: &str) -> bool {
        // Sound cards come and go (USB).
        (matches!(self.node, Node::Root) && (name.bytes().all(|b| b.is_ascii_digit()) || name == "asound"))
            || matches!(self.node, Node::Asound(_))
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        match &self.node {
            Node::Root => {
                if name == "self" {
                    return Ok(self.inode(Node::SelfLink));
                }
                if name == "thread-self" {
                    return Ok(self.inode(Node::ThreadSelf));
                }
                if name == "net" {
                    return Ok(self.inode(Node::NetDir));
                }
                if name == "sys" {
                    return Ok(self.inode(Node::Sys("sys/")));
                }
                if name == "asound" {
                    return Ok(self.inode(Node::Asound(String::new())));
                }
                if let Some(f) = GLOBAL_FILES.iter().find(|f| **f == name && global_present(f)) {
                    return Ok(self.inode(Node::Global(f)));
                }
                let pid: Pid = name.parse().map_err(|_| ENOENT)?;
                let host = if self.ns.level == 0 {
                    process(pid)?.pid
                } else {
                    let p = proc::all().into_iter().find(|p| p.pid_in(&self.ns) == Some(pid)).ok_or(ENOENT)?;
                    process(p.pid)?.pid
                };
                Ok(self.inode(Node::PidDir(host)))
            }
            Node::Sys(dir @ ("sys/net/ipv4/conf/" | "sys/net/ipv6/conf/")) => {
                let v6 = dir.contains("ipv6");
                if !conf_devices().iter().any(|d| d == name) {
                    return Err(ENOENT);
                }
                Ok(self.inode(Node::NetConf { v6, dev: name.into(), key: None }))
            }
            Node::NetConf { v6, dev, key: None } => {
                let key = conf_keys(*v6).iter().find(|k| k.0 == name).ok_or(ENOENT)?.0;
                Ok(self.inode(Node::NetConf { v6: *v6, dev: dev.clone(), key: Some(key) }))
            }
            Node::Sys(dir) if dir.ends_with('/') => {
                let e = sys_entry(&format!("{dir}{name}")).ok_or(ENOENT)?;
                Ok(self.inode(Node::Sys(e)))
            }
            Node::TaskDir(pid) => {
                let local: u64 = name.parse().map_err(|_| ENOENT)?;
                let p = process(*pid)?;
                let t = p.threads().into_iter().find(|t| p.tid_in(t.tid, &self.ns) == Some(local)).ok_or(ENOENT)?;
                Ok(self.inode(Node::Task(*pid, t.tid)))
            }
            Node::PidDir(pid) | Node::Task(pid, _) => {
                if name == "task" && matches!(self.node, Node::PidDir(_)) {
                    return Ok(self.inode(Node::TaskDir(*pid)));
                }
                if name == "fd" {
                    return Ok(self.inode(Node::FdDir(*pid)));
                }
                if name == "fdinfo" {
                    return Ok(self.inode(Node::FdInfoDir(*pid)));
                }
                if name == "ns" {
                    let tid = if let Node::Task(_, t) = self.node { t } else { 0 };
                    return Ok(self.inode(Node::NsDir(*pid, tid)));
                }
                if let Node::Task(_, tid) = self.node
                    && let Some(f) = THREAD_FILES.iter().find(|f| **f == name)
                {
                    return Ok(self.inode(Node::ThreadFile(*pid, tid, f)));
                }
                if let Some(f) = PID_FILES.iter().find(|f| **f == name) {
                    return Ok(self.inode(Node::PidFile(*pid, f)));
                }
                if let Some(l) = PID_LINKS.iter().find(|l| **l == name) {
                    return Ok(self.inode(Node::PidLink(*pid, l)));
                }
                Err(ENOENT)
            }
            Node::NetDir => {
                let f = NET_FILES.iter().find(|f| **f == name).ok_or(ENOENT)?;
                Ok(self.inode(Node::NetFile(f)))
            }
            Node::Asound(dir) => {
                let path = if dir.is_empty() { String::from(name) } else { format!("{dir}/{name}") };
                match crate::drivers::sound::proc_entry(dir) {
                    Some(crate::drivers::sound::ProcEntry::Dir(entries)) if entries.iter().any(|(n, _)| n == name) => {
                        Ok(self.inode(Node::Asound(path)))
                    }
                    Some(crate::drivers::sound::ProcEntry::Dir(_)) => Err(ENOENT),
                    _ => Err(ENOTDIR),
                }
            }
            Node::NsDir(pid, tid) => {
                let k = proc::ns::KINDS.iter().find(|k| **k == name).ok_or(ENOENT)?;
                Ok(self.inode(Node::NsLink(*pid, *tid, k)))
            }
            Node::FdDir(pid) => {
                let fd: i32 = name.parse().map_err(|_| ENOENT)?;
                private(*pid)?.files.lock().get(fd).map_err(|_| ENOENT)?;
                Ok(self.inode(Node::FdLink(*pid, fd)))
            }
            Node::FdInfoDir(pid) => {
                let fd: i32 = name.parse().map_err(|_| ENOENT)?;
                private(*pid)?.files.lock().get(fd).map_err(|_| ENOENT)?;
                Ok(self.inode(Node::FdInfo(*pid, fd)))
            }
            _ => Err(ENOTDIR),
        }
    }

    fn readdir(&self) -> Result<Vec<DirEntry>> {
        let mut out = Vec::new();
        let mut add = |name: String, node: Node, kind| {
            let pos = out.len() as u64;
            out.push(DirEntry { ino: ino_of(&node), name, kind, pos });
        };
        match &self.node {
            Node::Root => {
                add("self".into(), Node::SelfLink, FileType::Symlink);
                add("thread-self".into(), Node::ThreadSelf, FileType::Symlink);
                add("net".into(), Node::NetDir, FileType::Directory);
                add("sys".into(), Node::Sys("sys/"), FileType::Directory);
                add("asound".into(), Node::Asound(String::new()), FileType::Directory);
                for f in GLOBAL_FILES.iter().filter(|f| global_present(f)) {
                    add(f.to_string(), Node::Global(f), FileType::Regular);
                }
                for p in proc::all().into_iter().filter(|p| proc::domain::may_inspect(p)) {
                    if let Some(local) = self.local(p.pid) {
                        add(local.to_string(), Node::PidDir(p.pid), FileType::Directory);
                    }
                }
            }
            Node::TaskDir(pid) => {
                let p = process(*pid)?;
                for t in p.threads() {
                    if let Some(local) = p.tid_in(t.tid, &self.ns) {
                        add(local.to_string(), Node::Task(*pid, t.tid), FileType::Directory);
                    }
                }
            }
            Node::PidDir(pid) | Node::Task(pid, _) => {
                if matches!(self.node, Node::PidDir(_)) {
                    add("task".into(), Node::TaskDir(*pid), FileType::Directory);
                }
                add("fd".into(), Node::FdDir(*pid), FileType::Directory);
                add("fdinfo".into(), Node::FdInfoDir(*pid), FileType::Directory);
                let tid = if let Node::Task(_, t) = self.node { t } else { 0 };
                add("ns".into(), Node::NsDir(*pid, tid), FileType::Directory);
                for f in PID_FILES {
                    let node = match self.node {
                        Node::Task(_, tid) if THREAD_FILES.contains(f) => Node::ThreadFile(*pid, tid, f),
                        _ => Node::PidFile(*pid, f),
                    };
                    add(f.to_string(), node, FileType::Regular);
                }
                for l in PID_LINKS {
                    add(l.to_string(), Node::PidLink(*pid, l), FileType::Symlink);
                }
            }
            Node::NetDir => {
                for f in NET_FILES {
                    add(f.to_string(), Node::NetFile(f), FileType::Regular);
                }
            }
            Node::Asound(dir) => {
                if let Some(crate::drivers::sound::ProcEntry::Dir(entries)) = crate::drivers::sound::proc_entry(dir) {
                    for (n, is_dir) in entries {
                        let path = if dir.is_empty() { n.clone() } else { format!("{dir}/{n}") };
                        let kind = if is_dir { FileType::Directory } else { FileType::Regular };
                        add(n, Node::Asound(path), kind);
                    }
                }
            }
            Node::Sys(dir @ ("sys/net/ipv4/conf/" | "sys/net/ipv6/conf/")) => {
                let v6 = dir.contains("ipv6");
                for d in conf_devices() {
                    add(d.clone(), Node::NetConf { v6, dev: d, key: None }, FileType::Directory);
                }
            }
            Node::NetConf { v6, dev, key: None } => {
                for (k, _) in conf_keys(*v6) {
                    add(k.to_string(), Node::NetConf { v6: *v6, dev: dev.clone(), key: Some(k) }, FileType::Regular);
                }
            }
            Node::Sys(dir) if dir.ends_with('/') => {
                for e in SYS_TREE {
                    let Some(rest) = e.strip_prefix(*dir) else { continue };
                    let name = rest.trim_end_matches('/');
                    if name.is_empty() || name.contains('/') {
                        continue;
                    }
                    let ft = if rest.ends_with('/') { FileType::Directory } else { FileType::Regular };
                    add(name.to_string(), Node::Sys(e), ft);
                }
            }
            Node::NsDir(pid, tid) => {
                for k in proc::ns::KINDS {
                    add(k.to_string(), Node::NsLink(*pid, *tid, k), FileType::Symlink);
                }
            }
            Node::FdDir(pid) => {
                let fds: Vec<i32> = private(*pid)?.files.lock().iter().map(|(fd, _)| fd).collect();
                for fd in fds {
                    add(fd.to_string(), Node::FdLink(*pid, fd), FileType::Symlink);
                }
            }
            Node::FdInfoDir(pid) => {
                let fds: Vec<i32> = private(*pid)?.files.lock().iter().map(|(fd, _)| fd).collect();
                for fd in fds {
                    add(fd.to_string(), Node::FdInfo(*pid, fd), FileType::Regular);
                }
            }
            _ => return Err(ENOTDIR),
        }
        Ok(out)
    }

    fn readlink(&self) -> Result<String> {
        match &self.node {
            Node::SelfLink => Ok(self.local(proc::current().ok_or(ENOENT)?.pid).ok_or(ENOENT)?.to_string()),
            Node::ThreadSelf => {
                let p = proc::current().ok_or(ENOENT)?;
                let tid = p.tid_in(crate::sched::current().tid, &self.ns).ok_or(ENOENT)?;
                Ok(format!("{}/task/{tid}", self.local(p.pid).ok_or(ENOENT)?))
            }
            Node::NsLink(pid, tid, kind) => {
                let p = private(*pid)?;
                proc::ns::link(&p, &thread_ns(&p, *tid), kind).ok_or(ENOENT)
            }
            // Each lock is released before visible_path takes the reader's
            // root_dir lock (which may be this very process's).
            Node::PidLink(pid, "cwd") => {
                let d = private(*pid)?.cwd();
                Ok(visible_path(&d))
            }
            Node::PidLink(pid, "exe") => {
                let d = private(*pid)?.exe.lock().clone().ok_or(ENOENT)?;
                Ok(visible_path(&d))
            }
            Node::PidLink(pid, "root") => {
                let d = private(*pid)?.root_dir();
                Ok(visible_path(&d))
            }
            Node::FdLink(pid, fd) => {
                let f = private(*pid)?.files.lock().get(*fd).map_err(|_| ENOENT)?;
                Ok(match f.dentry() {
                    // Files with no name anywhere (memfds): "/name (deleted)".
                    Some(d) if d.parent.is_none() && !Arc::ptr_eq(&d, &root()) => format!("/{} (deleted)", d.name),
                    Some(d) => visible_path(&d),
                    None => {
                        let m = f.stat()?;
                        let console = makedev(super::devices::TTYAUX_MAJOR, super::devices::CONSOLE_MINOR);
                        if m.mode & S_IFMT == S_IFIFO {
                            format!("pipe:[{}]", m.ino)
                        } else if m.mode & S_IFMT == S_IFSOCK {
                            format!("socket:[{}]", m.ino)
                        } else if m.mode & S_IFMT == S_IFCHR && m.rdev == console {
                            "/dev/console".into()
                        } else {
                            "anon_inode:[file]".into()
                        }
                    }
                })
            }
            _ => Err(EINVAL),
        }
    }

    /// /proc/<pid>/ns/* open the namespace; /proc/<pid>/fd/* the open
    /// file itself, even when it has no name (proc(5)).
    fn magic_target(&self) -> Option<Arc<Dentry>> {
        match &self.node {
            Node::NsLink(pid, tid, kind) => {
                let p = private(*pid).ok()?;
                let n = thread_ns(&p, *tid);
                use crate::fs::NsRef;
                let r = match *kind {
                    "cgroup" => NsRef::Cgroup(n.cgroup),
                    "ipc" => NsRef::Ipc(n.ipc),
                    "mnt" => NsRef::Mnt(n.mnt),
                    "net" => NsRef::Net(n.net),
                    "pid" => NsRef::Pid(p.pid_ns()),
                    "pid_for_children" => NsRef::Pid(n.pid_for_children),
                    "user" => NsRef::User(p.cred().user_ns.clone()),
                    _ => NsRef::Uts(n.uts),
                };
                let name = proc::ns::link(&p, &thread_ns(&p, *tid), kind)?;
                Some(anon_dentry(&name, Arc::new(crate::fs::NsInode(r)), "nsfs"))
            }
            Node::FdLink(pid, fd) => {
                let f = private(*pid).ok()?.files.lock().get(*fd).ok()?;
                Some(match f.dentry() {
                    Some(d) => d,
                    None => anon_dentry("anon_inode", Arc::new(crate::fs::FdInode(f)), "anon_inodefs"),
                })
            }
            Node::PidLink(pid, "cwd") => Some(private(*pid).ok()?.cwd()),
            Node::PidLink(pid, "root") => Some(private(*pid).ok()?.root_dir()),
            Node::PidLink(pid, "exe") => private(*pid).ok()?.exe.lock().clone(),
            _ => None,
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if let Node::Global(KERNEL_FILE) = self.node {
            return KernelFile::open(0)?.pread(offset, buf);
        }
        let data = self.generate()?;
        let start = (offset as usize).min(data.len());
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data[start..start + n]);
        Ok(n)
    }

    fn open_special(self: Arc<Self>, flags: u32) -> Option<Result<Arc<dyn File>>> {
        match self.node {
            Node::PidFile(pid, "environ" | "maps") | Node::FdInfo(pid, _) | Node::FdDir(pid) | Node::FdInfoDir(pid)
                if flags & crate::fs::O_PATH == 0 =>
            {
                private(pid).err().map(Err)
            }
            Node::Global(STRACE_FILE) => Some(Ok(Arc::new(StraceControl { flags, offset: IrqSpinLock::new(0) }))),
            Node::Global(KERNEL_FILE) => Some(KernelFile::open(flags).map(|f| Arc::new(f) as Arc<dyn File>)),
            Node::Global(PROFILE_FILE) if crate::proc::cred::current().euid != 0 => Some(Err(EACCES)),
            Node::Global(PROFILE_FILE) => {
                // The report as it was when opened; a write starts or stops a profile.
                let data = crate::proc::profile::report().into_bytes();
                Some(Ok(Arc::new(ProfileControl { flags, data, offset: IrqSpinLock::new(0) })))
            }
            Node::Sys(p) if p.ends_with('/') => None,
            Node::NetConf { key: None, .. } => None,
            Node::Asound(ref p)
                if !matches!(
                    crate::drivers::sound::proc_entry(p.as_str()),
                    Some(crate::drivers::sound::ProcEntry::File(_))
                ) =>
            {
                None
            }
            // A thread's name, writable by its own process (proc(5)).
            Node::ThreadFile(pid, tid, "comm") => Some(self.generate().map(|data| {
                let target = Some(WriteTarget::Comm(pid, tid));
                let f: Arc<dyn File> = Arc::new(Snapshot { data, offset: IrqSpinLock::new(0), flags, target });
                f
            })),
            Node::Global(_)
            | Node::PidFile(..)
            | Node::NetFile(_)
            | Node::Sys(_)
            | Node::NetConf { .. }
            | Node::Asound(_) => Some(self.generate().map(|data| {
                let target = match &self.node {
                    Node::PidFile(pid, "comm") => Some(WriteTarget::Comm(*pid, u64::from(*pid))),
                    Node::PidFile(pid, f) if PID_WRITABLE.contains(f) => Some(WriteTarget::Pid(*pid, f)),
                    Node::Sys(path) if sys_writable(path) => Some(WriteTarget::Sys(path)),
                    Node::NetConf { v6, dev, key: Some(k) } => Some(WriteTarget::Conf(*v6, dev.clone(), k)),
                    _ => None,
                };
                let f: Arc<dyn File> = Arc::new(Snapshot { data, offset: IrqSpinLock::new(0), flags, target });
                f
            })),
            _ => None,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// What writing an opened /proc file changes.
#[derive(Clone)]
enum WriteTarget {
    Pid(Pid, &'static str),
    /// A thread's name (the main thread's is the process's).
    Comm(Pid, u64),
    Sys(&'static str),
    /// An interface's setting (ipv6, device, key).
    Conf(bool, String, &'static str),
}

/// An opened /proc file: the contents generated at open time.
struct Snapshot {
    data: Vec<u8>,
    offset: IrqSpinLock<usize>,
    flags: u32,
    /// For writable pid files: the process and file.
    target: Option<WriteTarget>,
}

impl File for Snapshot {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut off = self.offset.lock();
        let n = buf.len().min(self.data.len().saturating_sub(*off));
        buf[..n].copy_from_slice(&self.data[*off..*off + n]);
        *off += n;
        Ok(n)
    }
    fn pread(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let start = (offset as usize).min(self.data.len());
        let n = buf.len().min(self.data.len() - start);
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        Ok(n)
    }
    fn seek(&self, offset: i64, whence: u32) -> Result<u64> {
        let mut off = self.offset.lock();
        let base = match whence {
            super::SEEK_SET => 0,
            super::SEEK_CUR => *off as i64,
            super::SEEK_END => self.data.len() as i64,
            _ => return Err(EINVAL),
        };
        let n = base.checked_add(offset).filter(|n| *n >= 0).ok_or(EINVAL)?;
        *off = n as usize;
        Ok(n as u64)
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        match self.target.clone().ok_or(EINVAL)? {
            WriteTarget::Pid(pid, name) => write_pid_file(&*process(pid)?, name, buf),
            WriteTarget::Comm(pid, tid) => write_comm(pid, tid, buf),
            WriteTarget::Sys(path) => write_sys_file(path, buf),
            WriteTarget::Conf(v6, dev, key) => write_conf(v6, &dev, key, buf),
        }
    }
    fn stat(&self) -> Result<Metadata> {
        Ok(meta(0, S_IFREG | if self.target.is_some() { 0o644 } else { 0o444 }))
    }
    fn status_flags(&self) -> u32 {
        self.flags
    }
}

/// Name a thread of the caller's own process, as PR_SET_NAME does: its
/// first 15 bytes, without the newline (proc(5): "a thread may modify the
/// comm value of any other thread in the same thread group").
fn write_comm(pid: Pid, tid: u64, buf: &[u8]) -> Result<usize> {
    let p = process(pid)?;
    if proc::current().is_none_or(|me| me.pid != p.pid) {
        return Err(EINVAL);
    }
    let text = written_text(buf)?;
    let name: String = text.strip_suffix('\n').unwrap_or(text).chars().take(15).collect();
    if tid == u64::from(p.pid) {
        *p.name.lock() = name;
    } else {
        let t = p.threads().into_iter().find(|t| t.tid == tid).ok_or(ESRCH)?;
        *t.comm.lock() = Some(name);
    }
    Ok(buf.len())
}

/// The most lines a uid_map or gid_map takes (user_namespaces(7)).
const MAX_MAP_LINES: usize = 340;

/// Write a pid file: the ID maps and setgroups of the process's user
/// namespace, by the rules of user_namespaces(7) ("Defining user and group
/// ID mappings"), or oom_score_adj (the out-of-memory killer's
/// preference; lowering it needs CAP_SYS_RESOURCE).
/// What was written to a /proc file, as text: up to the first NUL, as the
/// kernel reads it (writers often include a C string's terminator).
fn written_text(buf: &[u8]) -> Result<&str> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..end]).map_err(|_| EINVAL)
}

fn write_pid_file(target: &proc::Process, name: &str, buf: &[u8]) -> Result<usize> {
    use crate::proc::cred::{CAP_SETGID, CAP_SETUID, CAP_SYS_ADMIN};
    use proc::ns::IdMapping;
    let text = written_text(buf)?;
    if name == "oom_score_adj" {
        let v: i32 = text.trim().parse().map_err(|_| EINVAL)?;
        if !(-1000..=1000).contains(&v) {
            return Err(EINVAL);
        }
        let old = target.oom_score_adj.load(Ordering::Relaxed);
        if v < old && !crate::proc::cred::current().capable(crate::proc::cred::CAP_SYS_RESOURCE) {
            return Err(EACCES);
        }
        target.oom_score_adj.store(v, Ordering::Relaxed);
        return Ok(buf.len());
    }
    let me = proc::current().ok_or(ESRCH)?.cred();
    let ns = target.cred().user_ns.clone();
    let parent = ns.parent.clone().ok_or(EPERM)?;
    // The writer must be in the namespace or its parent.
    if !Arc::ptr_eq(&me.user_ns, &ns) && !Arc::ptr_eq(&me.user_ns, &parent) {
        crate::log_info!(
            "{name} of pid {}: refused (the writer is in neither its namespace nor the parent)",
            target.pid
        );
        return Err(EPERM);
    }
    if name == "setgroups" {
        let allow = match text.trim() {
            "allow" => true,
            "deny" => false,
            _ => return Err(EINVAL),
        };
        if !ns.gid_map.lock().is_empty() || !me.ns_capable(&ns, CAP_SYS_ADMIN) {
            return Err(EPERM);
        }
        // "deny" inherited from the parent can't become "allow".
        if allow && !*parent.setgroups.lock() {
            return Err(EPERM);
        }
        *ns.setgroups.lock() = allow;
        return Ok(buf.len());
    }
    let uid = name == "uid_map";
    // A refused map says why in the kernel log (user_namespaces(7) has
    // several rules, and sandboxes rarely say which one they hit).
    let refuse = |why: &str| {
        crate::log_info!("{name} of pid {}: refused ({why}): {:?}", target.pid, text.trim());
        Err(EPERM)
    };
    let mut map = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut f = line.split_whitespace().map(|x| x.parse::<u32>());
        let (Some(Ok(inside)), Some(Ok(outside)), Some(Ok(count)), None) = (f.next(), f.next(), f.next(), f.next())
        else {
            return Err(EINVAL);
        };
        if count == 0 || inside.checked_add(count - 1).is_none() || outside.checked_add(count - 1).is_none() {
            return Err(EINVAL);
        }
        map.push(IdMapping { inside, outside, count });
    }
    if map.is_empty() || map.len() > MAX_MAP_LINES {
        return Err(EINVAL);
    }
    let overlaps = |a: u32, b: u32, n: u32, m: u32| a < b.saturating_add(m) && b < a.saturating_add(n);
    for (i, x) in map.iter().enumerate() {
        for y in &map[i + 1..] {
            if overlaps(x.inside, y.inside, x.count, y.count) || overlaps(x.outside, y.outside, x.count, y.count) {
                return Err(EINVAL);
            }
        }
    }
    // Every outside ID must exist in the parent namespace.
    for m in &map {
        for id in [m.outside, m.outside + (m.count - 1)] {
            let ok = if uid { parent.uid_to_kernel(id).is_some() } else { parent.gid_to_kernel(id).is_some() };
            if !ok {
                return refuse("an outside ID the parent namespace doesn't map");
            }
        }
    }
    let cap = if uid { CAP_SETUID } else { CAP_SETGID };
    if !me.ns_capable(&ns, cap) {
        return refuse("no capability over the namespace");
    }
    // Arbitrary maps need the capability in the parent; otherwise one line
    // mapping the writer's own effective ID (and for groups, setgroups
    // denied first).
    if !me.ns_capable(&parent, cap) {
        let own = if uid { parent.uid_from_kernel(me.euid) } else { parent.gid_from_kernel(me.egid) };
        if map.len() != 1 || map[0].count != 1 || Some(map[0].outside) != own {
            return refuse("without the capability over the parent, only the writer's own ID");
        }
        if !uid && *ns.setgroups.lock() {
            return refuse("setgroups is not denied");
        }
    }
    let slot = if uid { &ns.uid_map } else { &ns.gid_map };
    let mut g = slot.lock();
    if !g.is_empty() {
        drop(g);
        return refuse("already written");
    }
    *g = map;
    Ok(buf.len())
}

/// /proc/slate_strace: reads give the traced names, a write replaces them.
struct StraceControl {
    flags: u32,
    offset: IrqSpinLock<usize>,
}

impl File for StraceControl {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut off = self.offset.lock();
        let n = self.pread(*off as u64, buf)?;
        *off += n;
        Ok(n)
    }
    fn pread(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let data = alloc::format!("{}\n", crate::abi::linux::trace::get());
        let start = (offset as usize).min(data.len());
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data.as_bytes()[start..start + n]);
        Ok(n)
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        crate::abi::linux::trace::set(core::str::from_utf8(buf).map_err(|_| EINVAL)?);
        Ok(buf.len())
    }
    fn stat(&self) -> Result<Metadata> {
        Ok(meta(0, S_IFREG | 0o644))
    }
    fn status_flags(&self) -> u32 {
        self.flags
    }
}

/// /proc/slate_kernel: the kernel's own file, read where the loader put it
/// (too big for a copy on the kernel heap).
struct KernelFile {
    flags: u32,
    data: &'static [u8],
    offset: IrqSpinLock<usize>,
}

impl KernelFile {
    fn open(flags: u32) -> Result<KernelFile> {
        if crate::proc::cred::current().euid != 0 {
            return Err(EACCES);
        }
        let data = crate::boot::kernel_file().ok_or(ENOENT)?;
        Ok(KernelFile { flags, data, offset: IrqSpinLock::new(0) })
    }
}

impl File for KernelFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut off = self.offset.lock();
        let n = self.pread(*off as u64, buf)?;
        *off += n;
        Ok(n)
    }
    fn pread(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let start = (offset as usize).min(self.data.len());
        let n = buf.len().min(self.data.len() - start);
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        Ok(n)
    }
    fn stat(&self) -> Result<Metadata> {
        let mut m = meta(0, S_IFREG | 0o400);
        m.size = self.data.len() as u64;
        Ok(m)
    }
    fn status_flags(&self) -> u32 {
        self.flags
    }
}

/// /proc/slate_profile: reads give the profile, a write starts a new one
/// (or stops it, when empty).
struct ProfileControl {
    flags: u32,
    data: Vec<u8>,
    offset: IrqSpinLock<usize>,
}

impl File for ProfileControl {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut off = self.offset.lock();
        let n = self.pread(*off as u64, buf)?;
        *off += n;
        Ok(n)
    }
    fn pread(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let start = (offset as usize).min(self.data.len());
        let n = buf.len().min(self.data.len() - start);
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        Ok(n)
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        crate::proc::profile::set(core::str::from_utf8(buf).map_err(|_| EINVAL)?);
        Ok(buf.len())
    }
    fn stat(&self) -> Result<Metadata> {
        Ok(meta(0, S_IFREG | 0o600))
    }
    fn status_flags(&self) -> u32 {
        self.flags
    }
}

/// A thread's state as /proc shows it: R running or runnable, else S.
fn thread_state_char(t: &crate::sched::Thread) -> char {
    if matches!(t.state(), crate::sched::State::Running | crate::sched::State::Runnable) { 'R' } else { 'S' }
}

fn state_char(p: &proc::Process) -> char {
    if p.is_zombie() {
        'Z'
    } else if p
        .thread()
        .is_some_and(|t| matches!(t.state(), crate::sched::State::Running | crate::sched::State::Runnable))
    {
        // R is "running or runnable" (proc(5)): a thread waiting for a CPU
        // is not sleeping (LTP's futex tests wait for S before waking).
        'R'
    } else {
        'S'
    }
}

fn rss_pages(p: &proc::Process) -> u64 {
    p.aspace.lock().as_ref().map_or(0, |a| a.resident_pages())
}

/// /proc/<pid>/maps (proc(5)): one line per mapping, `start-end perms
/// offset dev inode path`; the brk area is `[heap]`. Device numbers are
/// not recorded (00:00), nor the stack or vDSO names (docs/GAPS.md).
fn process_maps(p: &proc::Process, s: &mut String) {
    // The mappings as they are, copied under the address space's lock;
    // the files are asked for their inode numbers after it (an inode's
    // metadata may take other locks, and the process's page faults wait
    // for this one: Firefox reads its maps with thousands of mappings).
    let vmas: Vec<_> = {
        let g = p.aspace.lock();
        let Some(a) = g.as_ref() else { return };
        a.vmas()
            .map(|v| {
                let heap = v.file.is_none() && v.start < a.brk.max(a.brk_start + 1) && v.end > a.brk_start;
                (v.start, v.end, v.prot, v.shared, v.file.clone(), heap)
            })
            .collect()
    };
    for (start, end, prot, shared, file, heap) in vmas {
        let perms = [
            if prot.read { 'r' } else { '-' },
            if prot.write { 'w' } else { '-' },
            if prot.exec { 'x' } else { '-' },
            if shared { 's' } else { 'p' },
        ];
        let perms: String = perms.iter().collect();
        let (offset, ino, name) = match &file {
            Some(f) => (f.offset, f.inode.metadata().ino, f.name.as_deref().unwrap_or("")),
            None if heap => (0, 0, "[heap]"),
            None => (0, 0, ""),
        };
        let mut line = alloc::format!("{start:08x}-{end:08x} {perms} {offset:08x} 00:00 {ino}");
        if !name.is_empty() {
            // The path starts in column 74, as proc(5)'s example shows.
            while line.len() < 73 {
                line.push(' ');
            }
            line.push(' ');
            line.push_str(name);
        }
        let _ = writeln!(s, "{line}");
    }
}

fn vsize(p: &proc::Process) -> u64 {
    p.aspace.lock().as_ref().map_or(0, |a| a.mapped_bytes())
}

impl ProcInode {
    fn generate(&self) -> Result<Vec<u8>> {
        let mut s = String::new();
        match &self.node {
            // Scheduler internals list every process: root only.
            Node::Global("slate_sched") if crate::proc::cred::current().euid != 0 => return Err(EACCES),
            Node::Global(name) => global(name, &mut s),
            Node::NetFile(name) => crate::net::proc_file(name, &mut s),
            Node::Asound(path) => match crate::drivers::sound::proc_entry(path) {
                Some(crate::drivers::sound::ProcEntry::File(text)) => s = text,
                _ => return Err(ENOENT),
            },
            Node::Sys(path) if !path.ends_with('/') => sys_file(path, &mut s),
            Node::NetConf { v6, dev, key: Some(k) } => {
                let _ = writeln!(s, "{}", conf_value(*v6, dev, k));
            }
            Node::FdInfo(pid, fd) => {
                let f = process(*pid)?.files.lock().get(*fd).map_err(|_| ENOENT)?;
                // proc(5): the offset, the status flags in octal, the mount.
                let pos = f.seek(0, 1).unwrap_or(0);
                let _ = write!(s, "pos:\t{pos}\nflags:\t0{:o}\nmnt_id:\t0\n", f.status_flags());
            }
            Node::PidFile(pid, name) => {
                let p = process(*pid)?;
                if *name == "cmdline" {
                    return Ok(p.cmdline.lock().clone());
                }
                per_process(&p, name, &mut s, &self.ns, None)?;
            }
            Node::ThreadFile(pid, tid, name) => {
                let p = process(*pid)?;
                let t = p.threads().into_iter().find(|t| t.tid == *tid).ok_or(ENOENT)?;
                per_process(&p, name, &mut s, &self.ns, Some(&t))?;
            }
            _ => return Err(EISDIR),
        }
        Ok(s.into_bytes())
    }
}

fn cpu_brand() -> String {
    let mut b = Vec::new();
    for leaf in 0x8000_0002u32..=0x8000_0004 {
        let (a, bx, c, d) = crate::arch::cpu::cpuid(leaf, 0);
        for r in [a, bx, c, d] {
            b.extend_from_slice(&r.to_le_bytes());
        }
    }
    String::from_utf8_lossy(&b).trim_matches(char::from(0)).trim().to_string()
}

fn global(name: &str, s: &mut String) {
    let mem = crate::mm::frame::stats();
    let uptime_ns = crate::time::monotonic_ns();
    match name {
        "cmdline" => {
            let _ = writeln!(s, "{}", crate::arch::boot::info().cmdline);
        }
        "cpuinfo" => {
            let brand = cpu_brand();
            let (_, _, ecx1, edx1) = crate::arch::cpu::cpuid(1, 0);
            let mut flags = Vec::new();
            for (bit, name) in [
                (0, "fpu"),
                (4, "tsc"),
                (5, "msr"),
                (6, "pae"),
                (8, "cx8"),
                (9, "apic"),
                (15, "cmov"),
                (23, "mmx"),
                (24, "fxsr"),
                (25, "sse"),
                (26, "sse2"),
            ] {
                if edx1 & (1 << bit) != 0 {
                    flags.push(name);
                }
            }
            for (bit, name) in [
                (0, "pni"),
                (9, "ssse3"),
                (19, "sse4_1"),
                (20, "sse4_2"),
                (23, "popcnt"),
                (25, "aes"),
                (26, "xsave"),
                (28, "avx"),
                (30, "rdrand"),
            ] {
                if ecx1 & (1 << bit) != 0 {
                    flags.push(name);
                }
            }
            for cpu in 0..crate::sched::cpu_count() {
                let _ = write!(
                    s,
                    "processor\t: {cpu}\nmodel name\t: {brand}\ncpu cores\t: {}\nflags\t\t: {}\n\n",
                    crate::sched::cpu_count(),
                    flags.join(" ")
                );
            }
        }
        "filesystems" => s.push_str(
            "nodev\tsysfs\nnodev\ttmpfs\nnodev\tproc\nnodev\tcgroup2\nnodev\tdevtmpfs\nnodev\tdevpts\nnodev\tmqueue\nnodev\toverlay\n\text4\n\tslatefs\n",
        ),
        "locks" => super::locks::proc_locks(s),
        "loadavg" => {
            // proc(5): three load averages, runnable/all threads, the last
            // PID handed out.
            let threads: usize = proc::all().iter().map(|p| p.threads().len()).sum();
            for l in crate::sched::load_average() {
                let hundredths = (l * 100 + (1 << (crate::sched::LOAD_FRACTION_BITS - 1))) >> crate::sched::LOAD_FRACTION_BITS;
                let _ = write!(s, "{}.{:02} ", hundredths / 100, hundredths % 100);
            }
            let last = crate::sched::next_id().saturating_sub(1);
            let _ = writeln!(s, "{}/{threads} {last}", crate::sched::runnable_threads());
        }
        "meminfo" => {
            let kb = |frames: u64| frames * 4;
            // Clean cached pages can be dropped: they count as available.
            let (cached, dirty) = super::pagecache::counts();
            let (cached, dirty) = (cached as u64, dirty as u64);
            // The block cache is Buffers (its blocks live on the heap, so
            // they are not Slab too); it can be dropped as well.
            let buffers = (crate::block::cache::bytes() / 4096) as u64;
            let _ = write!(
                s,
                "MemTotal:       {:8} kB\nMemFree:        {:8} kB\nMemAvailable:   {:8} kB\nBuffers:        {:8} kB\nCached:         {:8} kB\nSwapCached:            0 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\nDirty:          {:8} kB\nWriteback:             0 kB\nShmem:                 0 kB\nSlab:           {:8} kB\nCommitLimit:    {:8} kB\nCommitted_AS:   {:8} kB\n",
                kb(mem.usable_frames),
                kb(mem.free_frames),
                kb(mem.free_frames + cached.saturating_sub(dirty) + buffers),
                kb(buffers),
                kb(cached),
                kb(dirty),
                kb(crate::mm::heap::pages().saturating_sub(buffers)),
                kb(crate::mm::commit::limit_pages()),
                kb(crate::mm::commit::committed_pages())
            );
        }
        "mounts" => mounts(s),
        // proc(5): the I/O of each disk and mapped device (ADR 0112).
        "diskstats" => crate::block::diskstats(s),
        "partitions" => {
            // proc(5): major, minor, size in 1 KiB blocks, name.
            s.push_str("major minor  #blocks  name\n\n");
            for i in crate::block::list() {
                let (ma, mi) = (major(i.rdev), minor(i.rdev));
                let _ = writeln!(s, "{ma:4}  {mi:7} {:10} {}", i.sectors / 2, i.name);
            }
        }
        "slate_sched" => crate::sched::dump(s),
        "interrupts" => crate::arch::irq::proc_interrupts(s),
        "slate_drivers" => crate::drivers::proc_drivers(s),
        "slate_boot" => {
            // How this boot came about (ADR 0086): the loader, the kernel
            // file it loaded (each system version has its own), the
            // command line.
            let b = crate::boot::info();
            let _ = writeln!(s, "loader: {} {}", b.bootloader_name, b.bootloader_version);
            let _ = writeln!(s, "kernel: {}", b.kernel_path);
            let _ = writeln!(s, "cmdline: {}", b.cmdline);
        }
        "stat" => {
            // proc(5): user nice system idle iowait irq softirq steal guest
            // guest_nice, in USER_HZ (100 Hz) units; the tick is 1000 Hz.
            let per_cpu: Vec<[u64; 3]> = (0..crate::sched::cpu_count())
                .map(|c| {
                    let t = crate::sched::cpu_times(c);
                    [&t.user, &t.system, &t.idle].map(|v| v.load(Ordering::Relaxed) / 10_000_000)
                })
                .collect();
            let sum = per_cpu.iter().fold([0; 3], |a, c| [a[0] + c[0], a[1] + c[1], a[2] + c[2]]);
            let _ = writeln!(s, "cpu  {} 0 {} {} 0 0 0 0 0 0", sum[0], sum[1], sum[2]);
            for (c, t) in per_cpu.iter().enumerate() {
                let _ = writeln!(s, "cpu{c} {} 0 {} {} 0 0 0 0 0 0", t[0], t[1], t[2]);
            }
            let boot = (crate::time::realtime_ns() / 1_000_000_000) as i64 - (uptime_ns / 1_000_000_000) as i64;
            let _ = write!(
                s,
                "btime {boot}\nprocesses {}\nprocs_running {}\nprocs_blocked 0\n",
                proc::all().len(),
                crate::sched::runnable_threads()
            );
        }
        "uptime" => {
            let (secs, centis) = (uptime_ns / 1_000_000_000, uptime_ns / 10_000_000 % 100);
            let _ = writeln!(s, "{secs}.{centis:02} {secs}.{centis:02}");
        }
        "version" => s.push_str(crate::abi::linux::process::identity().3),
        _ => {}
    }
}

fn mounts(s: &mut String) {
    for m in super::vfs::mounts() {
        let (path, src) = (escape_mount_field(&m.path), escape_mount_field(&m.source));
        let _ = writeln!(s, "{src} {path} {} {} 0 0", m.fs_type, mount_options(m.flags));
    }
}

/// A mount's flags as /proc/mounts shows them: `ro` or `rw`, then
/// `nosuid`, `nodev` and `noexec`, then the access times' `noatime`,
/// `nodiratime` and `relatime` (proc(5), in the order Linux was seen to
/// print them; strictatime shows none).
fn mount_options(flags: u32) -> String {
    use super::vfs::{MNT_NOATIME, MNT_NODEV, MNT_NODIRATIME, MNT_NOEXEC, MNT_NOSUID, MNT_RDONLY, MNT_RELATIME};
    let mut o = String::from(if flags & MNT_RDONLY != 0 { "ro" } else { "rw" });
    for (f, name) in [
        (MNT_NOSUID, ",nosuid"),
        (MNT_NODEV, ",nodev"),
        (MNT_NOEXEC, ",noexec"),
        (MNT_NOATIME, ",noatime"),
        (MNT_NODIRATIME, ",nodiratime"),
        (MNT_RELATIME, ",relatime"),
    ] {
        if flags & f != 0 {
            o.push_str(name);
        }
    }
    o
}

/// Spaces, tabs, newlines and backslashes in mount fields are octal
/// escapes (proc(5)).
fn escape_mount_field(f: &str) -> String {
    let mut out = String::new();
    for c in f.chars() {
        match c {
            ' ' | '\t' | '\n' | '\\' => {
                let _ = write!(out, "\\{:03o}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// /proc/<pid>/mounts and mountinfo, for process `p`'s mount namespace
/// and root (proc(5)).
fn process_mounts(p: &proc::Process, info: bool, s: &mut String) {
    let root = p.root_dir();
    for m in super::vfs::mounts_of(p.mnt_ns_id(), &root) {
        let opt = mount_options(m.flags);
        let sb_opt = if m.flags & super::vfs::MNT_RDONLY != 0 { "ro" } else { "rw" };
        let (path, src) = (escape_mount_field(&m.path), escape_mount_field(&m.source));
        if info {
            // Every mount is private: no optional fields (ADR 0028).
            let _ = writeln!(
                s,
                "{} {} {}:{} / {path} {opt} - {} {src} {sb_opt}",
                m.id,
                m.parent_id,
                major(m.dev),
                minor(m.dev),
                m.fs_type
            );
        } else {
            let _ = writeln!(s, "{src} {path} {} {opt} 0 0", m.fs_type);
        }
    }
}

/// The files of a thread's directory that are its own (proc(5): its ID,
/// name, state, CPU time and counts).
const THREAD_FILES: &[&str] = &["comm", "stat", "status", "wchan"];

/// Process `p`'s file `name`, or with `thread` that thread's (for
/// [`THREAD_FILES`]: its ID, name, state, CPU time, CPU and counts).
fn per_process(
    p: &proc::Process,
    name: &str,
    s: &mut String,
    ns: &Arc<proc::ns::PidNs>,
    thread: Option<&Arc<crate::sched::Thread>>,
) -> Result<()> {
    let local = |pid: Pid| if ns.level == 0 { pid } else { proc::get(pid).and_then(|q| q.pid_in(ns)).unwrap_or(0) };
    let map_text = |m: &[proc::ns::IdMapping]| -> String {
        m.iter().map(|e| alloc::format!("{:>10} {:>10} {:>10}\n", e.inside, e.outside, e.count)).collect()
    };
    let comm = thread.and_then(|t| t.comm.lock().clone()).unwrap_or_else(|| p.name.lock().clone());
    let state = match thread {
        Some(t) if !p.is_zombie() => thread_state_char(t),
        _ => state_char(p),
    };
    // The thread the scheduling facts come from, and the ID shown.
    let sched_thread = thread.cloned().or_else(|| p.thread());
    let id = match thread {
        Some(t) => p.tid_in(t.tid, ns).unwrap_or(0) as Pid,
        None => local(p.pid),
    };
    let (own_cpu, counts) = match thread {
        Some(t) => (t.cpu_ns(), t.counts.get()),
        None => (p.cpu.own(), p.cpu.counts.get()),
    };
    let (pgid, sid) = (p.pgid.load(Ordering::Relaxed), p.sid.load(Ordering::Relaxed));
    match name {
        "comm" => {
            let _ = writeln!(s, "{comm}");
        }
        "environ" => {}
        "cgroup" => s.push_str(&super::cgroup::proc_line(p)),
        "uid_map" => s.push_str(&map_text(&p.cred().user_ns.uid_map.lock())),
        "gid_map" => s.push_str(&map_text(&p.cred().user_ns.gid_map.lock())),
        "setgroups" => s.push_str(if *p.cred().user_ns.setgroups.lock() { "allow\n" } else { "deny\n" }),
        "oom_score_adj" => {
            let _ = writeln!(s, "{}", p.oom_score_adj.load(Ordering::Relaxed));
        }
        "oom_score" => {
            let _ = writeln!(s, "{}", crate::proc::oom::score(p, None));
        }
        // proc(5): bytes and calls through read and write, then what
        // reached storage (512-byte blocks, getrusage's inblock and
        // oublock); no write is cancelled.
        "io" => {
            let c = &p.cpu.counts;
            let get = |a: &core::sync::atomic::AtomicU64| a.load(Ordering::Relaxed);
            let _ = write!(
                s,
                "rchar: {}\nwchar: {}\nsyscr: {}\nsyscw: {}\nread_bytes: {}\nwrite_bytes: {}\ncancelled_write_bytes: 0\n",
                get(&c.rchar),
                get(&c.wchar),
                get(&c.syscr),
                get(&c.syscw),
                get(&c.inblock) * 512,
                get(&c.oublock) * 512
            );
        }
        "limits" => {
            let _ = writeln!(s, "{:<25} {:<20} {:<20} {:<10}", "Limit", "Soft Limit", "Hard Limit", "Units");
            let show = |v: u64| {
                if v == crate::proc::rlimit::RLIM_INFINITY { "unlimited".into() } else { alloc::format!("{v}") }
            };
            for (r, (name, unit)) in crate::proc::rlimit::NAMES.iter().enumerate() {
                let l = p.rlimit(r);
                let _ = writeln!(s, "{name:<25} {:<20} {:<20} {unit:<10}", show(l.cur), show(l.max));
            }
        }
        "mounts" => process_mounts(p, false, s),
        "mountinfo" => process_mounts(p, true, s),
        "stat" => {
            // Field list: proc(5) "/proc/pid/stat".
            let start = p.start_ns / 10_000_000;
            // tty_nr and tpgid: the controlling terminal (proc(5): the
            // major number in bits 15-8, the minor in 31-20 and 7-0) and
            // its foreground process group, -1 without one.
            let ctty = p.ctty();
            let tty = ctty.as_ref().map_or(0, |t| {
                let (major, minor) = (crate::fs::vfs::major(t.rdev()), crate::fs::vfs::minor(t.rdev()));
                (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
            });
            let tpgid = ctty.as_ref().map_or(-1, |t| i64::from(t.foreground()));
            // priority: 20 + nice for normal threads, -1 - priority for
            // real-time ones, as the thread runs now (with a priority-
            // inheritance boost); then nice, and later rt_priority and
            // policy.
            let (policy, rt, nice, _) = sched_thread.as_ref().map_or((0, 0, 0, false), |t| t.sched_params());
            let prio = match sched_thread.as_ref().map(|t| t.class()) {
                Some(crate::sched::policy::Class::RealTime { priority, .. }) => -1 - i32::from(priority),
                _ => 20 + i32::from(nice),
            };
            let cpu = sched_thread.as_ref().map_or(0, |t| t.last_cpu());
            let _ = writeln!(
                s,
                "{} ({comm}) {state} {} {pgid} {sid} {tty} {tpgid} 0 {} {} {} {} {} {} {} {} {} {} {} 0 {start} {} {} 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 {cpu} {rt} {policy} 0 0 0 0 0 0 0 0 0 0 0",
                id,
                local(p.ppid()),
                // minflt cminflt majflt cmajflt.
                counts[0],
                p.cpu.children_counts.minflt.load(Ordering::Relaxed),
                counts[1],
                p.cpu.children_counts.majflt.load(Ordering::Relaxed),
                // utime stime cutime cstime, in USER_HZ units.
                own_cpu.0 / 10_000_000,
                own_cpu.1 / 10_000_000,
                p.cpu.children().0 / 10_000_000,
                p.cpu.children().1 / 10_000_000,
                prio,
                nice,
                p.threads().len().max(1),
                vsize(p),
                rss_pages(p)
            );
        }
        "maps" => process_maps(p, s),
        // size resident shared text lib data dt (proc(5)), in pages; lib
        // and dt are 0, as on Linux.
        "statm" => {
            let exe = p.exe.lock().as_ref().map(|d| d.inode.clone());
            let (shared, text, data) = p.aspace.lock().as_ref().map_or((0, 0, 0), |a| a.statm_parts(exe.as_ref()));
            let _ = writeln!(s, "{} {} {shared} {text} 0 {data} 0", vsize(p) / 4096, rss_pages(p));
        }
        // What the thread sleeps in (proc(5)): Slate names the system
        // call, where Linux names a kernel function; "0" when it isn't
        // waiting in one.
        "wchan" => {
            let t = sched_thread.as_ref();
            let nr = t.map_or(0, |t| t.syscall.load(Ordering::Relaxed));
            let asleep = matches!(state, 'S' | 'D' | 'I');
            let name = if p.abi() == proc::Abi::Native {
                slate_abi::nr::name(nr.wrapping_sub(1))
            } else {
                crate::abi::linux::nr::name(nr.wrapping_sub(1))
            };
            let name = if asleep && nr != 0 { name.unwrap_or("0") } else { "0" };
            s.push_str(&name.to_ascii_lowercase());
        }
        "status" => {
            let st = match state {
                'Z' => "Z (zombie)",
                'R' => "R (running)",
                _ => "S (sleeping)",
            };
            let c = p.cred();
            let (sc_mode, sc_filters) = {
                let s = p.seccomp.lock();
                (s.mode, s.filters.len())
            };
            // IDs as the reader's user namespace sees them.
            let me = crate::proc::cred::current();
            let groups: String = c.groups.iter().map(|g| alloc::format!("{} ", me.gid_out(*g))).collect();
            let _ = write!(
                s,
                "Name:\t{comm}\nUmask:\t{:04o}\nState:\t{st}\nTgid:\t{pid}\nPid:\t{id}\nPPid:\t{}\n\
                 Uid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nGroups:\t{groups}\n\
                 VmSize:\t{:8} kB\nVmHWM:\t{:8} kB\nVmRSS:\t{:8} kB\nVmSwap:\t{:8} kB\nThreads:\t{}\n\
                 CapInh:\t{:016x}\nCapPrm:\t{:016x}\nCapEff:\t{:016x}\nCapBnd:\t{:016x}\nCapAmb:\t{:016x}\n\
                 NoNewPrivs:\t{}\nSeccomp:\t{}\nSeccomp_filters:\t{}\nDomain:\t{}\n",
                p.umask(),
                local(p.ppid()),
                me.uid_out(c.ruid),
                me.uid_out(c.euid),
                me.uid_out(c.suid),
                me.uid_out(c.fsuid),
                me.gid_out(c.rgid),
                me.gid_out(c.egid),
                me.gid_out(c.sgid),
                me.gid_out(c.fsgid),
                vsize(p) / 1024,
                p.usage().maxrss_pages * 4,
                rss_pages(p) * 4,
                // No swap: Slate keeps everything in memory.
                0,
                p.threads().len().max(1),
                c.cap_inheritable,
                c.cap_permitted,
                c.cap_effective,
                c.cap_bounding,
                c.cap_ambient,
                u8::from(c.no_new_privs),
                sc_mode,
                sc_filters,
                p.domain().name(),
                pid = local(p.pid),
            );
            let [.., nvcsw, nivcsw] = counts;
            let _ = write!(s, "voluntary_ctxt_switches:\t{nvcsw}\nnonvoluntary_ctxt_switches:\t{nivcsw}\n");
            if let Some(svc) = p.service.lock().clone() {
                let _ = writeln!(s, "Service:\t{svc}");
            }
            if let Some(b) = p.box_tag.lock().clone() {
                let _ = writeln!(s, "Box:\t{b}");
            }
            if let Some(perms) = crate::proc::apps::describe(p.app()) {
                let _ = writeln!(s, "Permissions:\t{perms}");
            }
        }
        _ => return Err(ENOENT),
    }
    Ok(())
}
