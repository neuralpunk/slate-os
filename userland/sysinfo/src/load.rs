// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the computer is doing (ADR 0112), for the System Monitor: the
//! processors' times, memory, the network cards' and the disks' counts,
//! and the mounted file systems, in proc(5)'s formats. The monitor reads
//! them every few seconds and turns the differences into rates.

use alloc::string::String;
use alloc::vec::Vec;

/// A processor's times, in USER_HZ ticks: busy (user, nice, system, irq,
/// softirq, steal) and all of them (with idle and iowait).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuTime {
    pub busy: u64,
    pub total: u64,
}

impl CpuTime {
    /// The share of `self - before` that was busy, 0 to 1.
    pub fn busy_since(&self, before: &CpuTime) -> f32 {
        let total = self.total.saturating_sub(before.total);
        if total == 0 { 0.0 } else { (self.busy.saturating_sub(before.busy) as f32 / total as f32).min(1.0) }
    }
}

/// /proc/stat's `cpu` lines: the whole machine first, then each processor.
pub fn cpu_times(stat: &str) -> Vec<CpuTime> {
    stat.lines()
        .filter(|l| l.starts_with("cpu"))
        .map(|l| {
            let v: Vec<u64> = l.split_whitespace().skip(1).filter_map(|f| f.parse().ok()).collect();
            let at = |i: usize| v.get(i).copied().unwrap_or(0);
            // user nice system idle iowait irq softirq steal (guest and
            // guest_nice are in user and nice already).
            let idle = at(3) + at(4);
            let busy = at(0) + at(1) + at(2) + at(5) + at(6) + at(7);
            CpuTime { busy, total: busy + idle }
        })
        .collect()
}

/// /proc/meminfo's figures, in KiB.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Memory {
    pub total: u64,
    pub available: u64,
    pub cached: u64,
    pub buffers: u64,
}

impl Memory {
    /// What programs use: all but what is available.
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.available)
    }
}

pub fn memory(meminfo: &str) -> Memory {
    let field = |name: &str| -> u64 {
        meminfo
            .lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))
            .and_then(|r| r.split_whitespace().next()?.parse().ok())
            .unwrap_or(0)
    };
    Memory {
        total: field("MemTotal"),
        available: field("MemAvailable"),
        cached: field("Cached"),
        buffers: field("Buffers"),
    }
}

/// A network card's counts since it came up, in bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetCount {
    pub name: String,
    pub received: u64,
    pub sent: u64,
}

/// /proc/net/dev: each card but the loopback.
pub fn net_counts(text: &str) -> Vec<NetCount> {
    text.lines()
        .filter_map(|l| {
            let (name, rest) = l.split_once(':')?;
            let name = name.trim();
            let v: Vec<u64> = rest.split_whitespace().filter_map(|f| f.parse().ok()).collect();
            // Received: bytes packets errs drop fifo frame compressed
            // multicast; then sent: bytes...
            (name != "lo" && v.len() >= 9).then(|| NetCount { name: String::from(name), received: v[0], sent: v[8] })
        })
        .collect()
}

/// A disk's counts since it appeared, in 512-byte sectors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiskCount {
    pub name: String,
    pub read: u64,
    pub written: u64,
}

/// /proc/diskstats: Slate lists whole disks and mapped devices there (not
/// partitions).
pub fn disk_counts(text: &str) -> Vec<DiskCount> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // major minor name reads merged sectors ms writes merged sectors...
            let n = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok());
            Some(DiskCount { name: String::from(*f.get(2)?), read: n(5)?, written: n(9)? })
        })
        .collect()
}

/// A mounted file system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    pub source: String,
    pub path: String,
    pub fs: String,
}

/// /proc/mounts, with its octal escapes undone (`\040` is a space).
pub fn mounts(text: &str) -> Vec<Mount> {
    let unescape = |s: &str| -> String {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
                out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
                i += 4;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    text.lines()
        .filter_map(|l| {
            let mut f = l.split(' ');
            Some(Mount { source: unescape(f.next()?), path: unescape(f.next()?), fs: String::from(f.next()?) })
        })
        .collect()
}

/// The file systems that hold files people keep: not /proc, /sys, /dev
/// and the like.
pub fn is_storage(m: &Mount) -> bool {
    matches!(m.fs.as_str(), "ext2" | "ext3" | "ext4" | "slatefs" | "vfat" | "exfat" | "ntfs" | "iso9660" | "overlay")
}

/// A file system's size and free space, in bytes (statfs(2)).
pub fn usage(path: &str) -> Option<(u64, u64)> {
    let s = slate_rt::fs::statfs(path.as_bytes()).ok()?;
    let bs = s.block_size.max(0) as u64;
    Some((s.blocks * bs, s.available * bs))
}

/// Read a file of /proc as text (empty if it can't be read).
pub fn read(path: &str) -> String {
    slate_rt::fs::read_file(path.as_bytes()).map(|b| String::from(slate_rt::lossy(&b))).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processors_and_memory() {
        let stat =
            "cpu  100 0 50 850 0 0 0 0 0 0\ncpu0 60 0 20 420 0 0 0 0 0 0\ncpu1 40 0 30 430 0 0 0 0 0 0\nbtime 1\n";
        let t = cpu_times(stat);
        assert_eq!(t.len(), 3);
        assert_eq!(t[0], CpuTime { busy: 150, total: 1000 });
        let later = CpuTime { busy: 250, total: 1200 };
        assert!((later.busy_since(&t[0]) - 0.5).abs() < 1e-6);
        assert_eq!(t[0].busy_since(&t[0]), 0.0);
        let m =
            memory("MemTotal:  4000 kB\nMemFree: 1000 kB\nMemAvailable:   3000 kB\nBuffers: 10 kB\nCached: 500 kB\n");
        assert_eq!((m.total, m.available, m.used(), m.cached, m.buffers), (4000, 3000, 1000, 500, 10));
    }

    #[test]
    fn counts() {
        let net = "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes\n    lo: 5 1 0 0 0 0 0 0 5 1 0 0 0 0 0 0\n  eth0: 1000 10 0 0 0 0 0 0 200 3 0 0 0 0 0 0\n";
        assert_eq!(net_counts(net), std::vec![NetCount { name: "eth0".into(), received: 1000, sent: 200 }]);
        let disks = " 253       0 vda 10 0 80 1 5 0 40 2 0 3 3 0 0 0 0 0 0\n 259 0 nvme0n1 1 0 16 0 2 0 32 0 0 0 0\n 254 0 dm-0 3 0 24 0 1 0 8 0 0 0 0\n";
        let names: Vec<String> = disk_counts(disks).into_iter().map(|d| d.name).collect();
        assert_eq!(names, ["vda", "nvme0n1", "dm-0"]);
        assert_eq!(disk_counts(disks)[0], DiskCount { name: "vda".into(), read: 80, written: 40 });
    }

    #[test]
    fn mount_table() {
        let m =
            mounts("/dev/dm-0 / slatefs rw 0 0\nproc /proc proc rw 0 0\n/dev/sdb1 /run/media/a\\040b vfat rw 0 0\n");
        assert_eq!(m.len(), 3);
        assert_eq!(m[2].path, "/run/media/a b");
        let kept: Vec<&str> = m.iter().filter(|m| is_storage(m)).map(|m| m.path.as_str()).collect();
        assert_eq!(kept, ["/", "/run/media/a b"]);
    }
}
