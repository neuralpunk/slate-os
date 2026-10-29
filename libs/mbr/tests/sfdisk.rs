// SPDX-License-Identifier: MIT OR Apache-2.0

//! An MBR made by the host's sfdisk (util-linux), with primary, extended
//! and logical partitions, read back: our partitions are the ones
//! `sfdisk --dump` lists (observed behaviour, as SLATE_HANDOFF.md §3
//! allows). Skipped where sfdisk is not installed.

use std::process::{Command, Stdio};

use slate_mbr::{SECTOR, Table, logical, parse};

#[test]
fn matches_sfdisk() {
    let dir = std::env::temp_dir().join(format!("slate-mbr-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let img = dir.join("disk.img");
    std::fs::File::create(&img).unwrap().set_len(32 << 20).unwrap();
    let script = "label: dos\nstart=2048, size=4096, type=83, bootable\nstart=8192, size=40960, type=f\n\
                  start=10240, size=2048, type=83\nstart=14336, size=8192, type=7\nstart=26624, size=2048, type=82\n\
                  start=49152, size=4096, type=c\n";
    let Ok(mut child) = Command::new("sfdisk").arg("-q").arg(&img).stdin(Stdio::piped()).spawn() else {
        eprintln!("no sfdisk on this host; skipped");
        return;
    };
    use std::io::Write;
    child.stdin.take().unwrap().write_all(script.as_bytes()).unwrap();
    assert!(child.wait().unwrap().success(), "sfdisk failed");
    let dump = Command::new("sfdisk").arg("--dump").arg(&img).output().unwrap();
    let dump = String::from_utf8(dump.stdout).unwrap();

    // What sfdisk lists: (number, start, size, type).
    let want: Vec<(u32, u64, u64, u8)> = dump
        .lines()
        .filter_map(|l| {
            let (dev, rest) = l.split_once(" : ")?;
            let number = dev.trim().rsplit_once("img")?.1.parse().ok()?;
            let field = |k: &str| {
                rest.split(',').find_map(|f| f.trim().strip_prefix(k)).map(|v| v.trim_start_matches(['=', ' ']))
            };
            Some((
                number,
                field("start")?.parse().ok()?,
                field("size")?.parse().ok()?,
                u8::from_str_radix(field("type")?, 16).ok()?,
            ))
        })
        .collect();

    let data = std::fs::read(&img).unwrap();
    let sector = |n: u64| -> Option<[u8; SECTOR]> {
        data.get(n as usize * SECTOR..(n as usize + 1) * SECTOR).map(|s| s.try_into().unwrap())
    };
    let Table::Mbr { primary, .. } = parse(&data[..SECTOR], (data.len() / SECTOR) as u64) else {
        panic!("not read as an MBR")
    };
    assert!(primary[0].bootable);
    let mut got: Vec<(u32, u64, u64, u8)> = primary.iter().map(|p| (p.number, p.start, p.sectors, p.kind)).collect();
    for p in primary.iter().filter(|p| slate_mbr::extended(p)) {
        got.extend(logical(p, sector).iter().map(|l| (l.number, l.start, l.sectors, l.kind)));
    }
    got.sort();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(got, want, "sfdisk --dump:\n{dump}");
}
