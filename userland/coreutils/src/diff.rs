// SPDX-License-Identifier: MIT OR Apache-2.0

//! diff(1): line differences with the Myers O(ND) algorithm ("An O(ND)
//! Difference Algorithm and Its Variations", E. Myers, 1986), in the
//! normal, unified (-u/-U N) and brief (-q) formats, and -r for
//! directories. Exit status: 0 same, 1 different, 2 trouble.

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, io, lossy};

use crate::util::{Opt, Parser, bad_option, error, error_path, lines, parse_num, read_input};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Same,
    Del,
    Ins,
}

/// The edit script turning `a` into `b`, one op per line.
fn myers<T: PartialEq>(a: &[T], b: &[T]) -> Vec<Op> {
    let (n, m) = (a.len() as isize, b.len() as isize);
    let max = (n + m) as usize;
    let off = max as isize + 1;
    let at = |k: isize| (k + off) as usize;
    let mut v = alloc::vec![0isize; 2 * max + 3];
    // trace[d] is the frontier before step d.
    let mut trace: Vec<Vec<isize>> = Vec::new();
    'outer: for d in 0..=max as isize {
        trace.push(v.clone());
        let mut k = -d;
        while k <= d {
            let mut x =
                if k == -d || (k != d && v[at(k - 1)] < v[at(k + 1)]) { v[at(k + 1)] } else { v[at(k - 1)] + 1 };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[at(k)] = x;
            if x >= n && y >= m {
                break 'outer;
            }
            k += 2;
        }
    }
    let mut ops = Vec::new();
    let (mut x, mut y) = (n, m);
    for d in (0..trace.len() as isize).rev() {
        let v = &trace[d as usize];
        let k = x - y;
        let prev_k = if k == -d || (k != d && v[at(k - 1)] < v[at(k + 1)]) { k + 1 } else { k - 1 };
        let prev_x = v[at(prev_k)];
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y {
            ops.push(Op::Same);
            x -= 1;
            y -= 1;
        }
        if d > 0 {
            if x == prev_x {
                ops.push(Op::Ins);
                y -= 1;
            } else {
                ops.push(Op::Del);
                x -= 1;
            }
        }
    }
    ops.reverse();
    ops
}

#[derive(Debug, Default)]
struct Opts {
    unified: Option<usize>,
    brief: bool,
    recursive: bool,
    ignore_case: bool,
    ignore_space: bool,
    ignore_all_space: bool,
    new_file: bool,
    labels: Vec<Vec<u8>>,
}

fn norm(l: &[u8], o: &Opts) -> Vec<u8> {
    let mut v: Vec<u8> = if o.ignore_all_space {
        l.iter().copied().filter(|c| !c.is_ascii_whitespace()).collect()
    } else if o.ignore_space {
        let mut out = Vec::new();
        let mut sp = false;
        for &c in l {
            if c == b' ' || c == b'\t' {
                sp = true;
            } else {
                if sp && !out.is_empty() {
                    out.push(b' ');
                }
                sp = false;
                out.push(c);
            }
        }
        out
    } else {
        l.to_vec()
    };
    if o.ignore_case {
        v.make_ascii_lowercase();
    }
    v
}

fn range(start: usize, len: usize) -> String {
    match len {
        0 => alloc::format!("{start}"),
        1 => alloc::format!("{}", start + 1),
        _ => alloc::format!("{},{}", start + 1, start + len),
    }
}

fn mtime_label(path: &[u8]) -> String {
    let st = fs::stat(path).ok();
    let mut s = String::new();
    if let Some(st) = st {
        let tm = slate_rt::tz::localtime(st.mtime);
        slate_rt::time::format(&tm, "%Y-%m-%d %H:%M:%S", &mut s);
        s.push_str(&alloc::format!(".{:09} ", st.mtime_nsec));
        slate_rt::time::format(&tm, "%z", &mut s);
    }
    s
}

/// Compare two files' contents; returns 0 same, 1 different.
fn diff_files(pa: &[u8], pb: &[u8], da: &[u8], db: &[u8], o: &Opts, out: &mut Vec<u8>) -> i32 {
    if da == db {
        return 0;
    }
    let (la, lb) = (lines(da, b'\n'), lines(db, b'\n'));
    let (na, nb): (Vec<Vec<u8>>, Vec<Vec<u8>>) =
        (la.iter().map(|l| norm(l, o)).collect(), lb.iter().map(|l| norm(l, o)).collect());
    let ops = myers(&na, &nb);
    if ops.iter().all(|&op| op == Op::Same) {
        return 0;
    }
    if o.brief {
        out.extend_from_slice(alloc::format!("Files {} and {} differ\n", lossy(pa), lossy(pb)).as_bytes());
        return 1;
    }
    let no_nl_a = !da.is_empty() && da.last() != Some(&b'\n');
    let no_nl_b = !db.is_empty() && db.last() != Some(&b'\n');
    let line = |out: &mut Vec<u8>, prefix: &[u8], l: &[u8], last_no_nl: bool| {
        out.extend_from_slice(prefix);
        out.extend_from_slice(l);
        out.push(b'\n');
        if last_no_nl {
            out.extend_from_slice(b"\\ No newline at end of file\n");
        }
    };
    // Hunks: runs of changes as (a_start, a_len, b_start, b_len) with the
    // op positions they cover.
    let mut changes: Vec<(usize, usize, usize, usize)> = Vec::new();
    let (mut i, mut j, mut k) = (0, 0, 0);
    while k < ops.len() {
        if ops[k] == Op::Same {
            i += 1;
            j += 1;
            k += 1;
            continue;
        }
        let (si, sj) = (i, j);
        while k < ops.len() && ops[k] != Op::Same {
            if ops[k] == Op::Del {
                i += 1;
            } else {
                j += 1;
            }
            k += 1;
        }
        changes.push((si, i - si, sj, j - sj));
    }
    match o.unified {
        None => {
            for &(a0, alen, b0, blen) in &changes {
                let kind = if alen == 0 {
                    'a'
                } else if blen == 0 {
                    'd'
                } else {
                    'c'
                };
                let ar = if alen == 0 { alloc::format!("{a0}") } else { range(a0, alen) };
                let br = if blen == 0 { alloc::format!("{b0}") } else { range(b0, blen) };
                out.extend_from_slice(alloc::format!("{ar}{kind}{br}\n").as_bytes());
                for x in a0..a0 + alen {
                    line(out, b"< ", la[x], no_nl_a && x + 1 == la.len());
                }
                if alen > 0 && blen > 0 {
                    out.extend_from_slice(b"---\n");
                }
                for y in b0..b0 + blen {
                    line(out, b"> ", lb[y], no_nl_b && y + 1 == lb.len());
                }
            }
        }
        Some(ctx) => {
            let la_name = o
                .labels
                .first()
                .map_or_else(|| alloc::format!("{}\t{}", lossy(pa), mtime_label(pa)), |l| lossy(l).into_owned());
            let lb_name = o
                .labels
                .get(1)
                .map_or_else(|| alloc::format!("{}\t{}", lossy(pb), mtime_label(pb)), |l| lossy(l).into_owned());
            out.extend_from_slice(alloc::format!("--- {la_name}\n+++ {lb_name}\n").as_bytes());
            // Group changes whose contexts touch.
            let mut g = 0;
            while g < changes.len() {
                let mut h = g;
                while h + 1 < changes.len() && changes[h + 1].0 - (changes[h].0 + changes[h].1) <= 2 * ctx {
                    h += 1;
                }
                let a_start = changes[g].0.saturating_sub(ctx);
                let b_start = changes[g].2.saturating_sub(ctx);
                let a_end = (changes[h].0 + changes[h].1 + ctx).min(la.len());
                let b_end = (changes[h].2 + changes[h].3 + ctx).min(lb.len());
                let fmt = |s: usize, n: usize| {
                    if n == 1 {
                        alloc::format!("{}", s + 1)
                    } else if n == 0 {
                        alloc::format!("{s},0")
                    } else {
                        alloc::format!("{},{n}", s + 1)
                    }
                };
                out.extend_from_slice(
                    alloc::format!("@@ -{} +{} @@\n", fmt(a_start, a_end - a_start), fmt(b_start, b_end - b_start))
                        .as_bytes(),
                );
                let (mut x, mut y) = (a_start, b_start);
                for c in &changes[g..=h] {
                    while x < c.0 {
                        line(out, b" ", la[x], no_nl_a && x + 1 == la.len());
                        x += 1;
                        y += 1;
                    }
                    for _ in 0..c.1 {
                        line(out, b"-", la[x], no_nl_a && x + 1 == la.len());
                        x += 1;
                    }
                    for _ in 0..c.3 {
                        line(out, b"+", lb[y], no_nl_b && y + 1 == lb.len());
                        y += 1;
                    }
                }
                while x < a_end {
                    line(out, b" ", la[x], no_nl_a && x + 1 == la.len());
                    x += 1;
                }
                g = h + 1;
            }
        }
    }
    1
}

fn diff_paths(a: &[u8], b: &[u8], o: &Opts, out: &mut Vec<u8>) -> i32 {
    let (sa, sb) = (fs::stat(a), fs::stat(b));
    let (sa, sb) = match (sa, sb) {
        (Ok(x), Ok(y)) => (Some(x), Some(y)),
        (Err(_), Ok(y)) if o.new_file => (None, Some(y)),
        (Ok(x), Err(_)) if o.new_file => (Some(x), None),
        (Err(e), _) => {
            io::out(out);
            out.clear();
            error_path(a, e);
            return 2;
        }
        (_, Err(e)) => {
            io::out(out);
            out.clear();
            error_path(b, e);
            return 2;
        }
    };
    let dir_a = sa.is_some_and(|s| s.is_dir());
    let dir_b = sb.is_some_and(|s| s.is_dir());
    if dir_a && dir_b {
        let names = |p: &[u8]| -> Vec<Vec<u8>> {
            let mut v: Vec<Vec<u8>> = fs::read_dir(p).unwrap_or_default().into_iter().map(|e| e.name).collect();
            v.sort();
            v
        };
        let (na, nb) = (names(a), names(b));
        let mut all: Vec<Vec<u8>> = na.iter().chain(nb.iter()).cloned().collect();
        all.sort();
        all.dedup();
        let mut status = 0;
        for n in all {
            let (pa, pb) = (fs::join(a, &n), fs::join(b, &n));
            match (na.contains(&n), nb.contains(&n)) {
                (true, true) => {
                    let both_dirs = fs::stat(&pa).is_ok_and(|s| s.is_dir()) && fs::stat(&pb).is_ok_and(|s| s.is_dir());
                    if both_dirs && !o.recursive {
                        out.extend_from_slice(
                            alloc::format!("Common subdirectories: {} and {}\n", lossy(&pa), lossy(&pb)).as_bytes(),
                        );
                        continue;
                    }
                    let before = out.len();
                    let s = diff_paths(&pa, &pb, o, out);
                    if s == 1 && !o.brief && !both_dirs {
                        // GNU prints the command line for each file pair.
                        let mut cmd = String::from("diff");
                        if let Some(c) = o.unified {
                            cmd.push_str(&if c == 3 { String::from(" -u") } else { alloc::format!(" -U {c}") });
                        }
                        if o.recursive {
                            cmd.push_str(" -r");
                        }
                        let header = alloc::format!("{cmd} {} {}\n", lossy(&pa), lossy(&pb));
                        out.splice(before..before, header.bytes());
                    }
                    status = status.max(s);
                }
                (true, false) if !o.new_file => {
                    out.extend_from_slice(alloc::format!("Only in {}: {}\n", lossy(a), lossy(&n)).as_bytes());
                    status = status.max(1);
                }
                (false, true) if !o.new_file => {
                    out.extend_from_slice(alloc::format!("Only in {}: {}\n", lossy(b), lossy(&n)).as_bytes());
                    status = status.max(1);
                }
                _ => status = status.max(diff_paths(&pa, &pb, o, out)),
            }
        }
        return status;
    }
    if dir_a || dir_b {
        // A directory and a file: compare with the same name inside.
        let (da, db) =
            if dir_a { (fs::join(a, fs::basename(b)), b.to_vec()) } else { (a.to_vec(), fs::join(b, fs::basename(a))) };
        return diff_paths(&da, &db, o, out);
    }
    let da = if sa.is_some() { read_input(a) } else { Ok(Vec::new()) };
    let db = if sb.is_some() { read_input(b) } else { Ok(Vec::new()) };
    match (da, db) {
        (Ok(x), Ok(y)) => {
            if (x.contains(&0) || y.contains(&0)) && x != y {
                out.extend_from_slice(alloc::format!("Binary files {} and {} differ\n", lossy(a), lossy(b)).as_bytes());
                return 1;
            }
            diff_files(a, b, &x, &y, o, out)
        }
        (Err(e), _) => {
            error_path(a, e);
            2
        }
        (_, Err(e)) => {
            error_path(b, e);
            2
        }
    }
}

pub fn main(args: &[Vec<u8>]) -> i32 {
    let mut o = Opts::default();
    let mut ops = Vec::new();
    let mut p = Parser::new(args, b"UL");
    while let Some(opt) = p.next() {
        match opt {
            Opt::Short(b'u') => o.unified = Some(3),
            Opt::Short(b'U') => o.unified = Some(p.value().and_then(|v| parse_num(&v)).unwrap_or(3)),
            Opt::Short(b'q') => o.brief = true,
            Opt::Short(b'r') => o.recursive = true,
            Opt::Short(b'i') => o.ignore_case = true,
            Opt::Short(b'b') => o.ignore_space = true,
            Opt::Short(b'w') => o.ignore_all_space = true,
            Opt::Short(b'N') => o.new_file = true,
            Opt::Short(b'a') => {}
            Opt::Short(b'L') => o.labels.push(p.value().unwrap_or_default()),
            Opt::Long(l) => match l.as_str() {
                "unified" => o.unified = Some(p.inline_value().and_then(|v| parse_num(&v)).unwrap_or(3)),
                "brief" => o.brief = true,
                "recursive" => o.recursive = true,
                "ignore-case" => o.ignore_case = true,
                "ignore-space-change" => o.ignore_space = true,
                "ignore-all-space" => o.ignore_all_space = true,
                "new-file" => o.new_file = true,
                "label" => o.labels.push(p.value().unwrap_or_default()),
                "text" => {}
                _ => return bad_option(&Opt::Long(l)),
            },
            Opt::Operand(f) => ops.push(f),
            opt => return bad_option(&opt),
        }
    }
    if ops.len() != 2 {
        error(if ops.len() < 2 { "missing operand" } else { "extra operand" });
        return 2;
    }
    let mut out = Vec::new();
    let s = diff_paths(&ops[0], &ops[1], &o, &mut out);
    io::out(&out);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_scripts() {
        let a: Vec<char> = "ABCABBA".chars().collect();
        let b: Vec<char> = "CBABAC".chars().collect();
        let ops = myers(&a, &b);
        // Applying the script reproduces b, and it is minimal (D = 5).
        let edits = ops.iter().filter(|&&o| o != Op::Same).count();
        assert_eq!(edits, 5);
        let (mut i, mut out) = (0, Vec::new());
        let mut j = 0;
        for op in ops {
            match op {
                Op::Same => {
                    out.push(a[i]);
                    i += 1;
                    j += 1;
                }
                Op::Del => i += 1,
                Op::Ins => {
                    out.push(b[j]);
                    j += 1;
                }
            }
        }
        assert_eq!(out, b);
        assert!(myers::<u8>(&[], &[]).is_empty());
        assert_eq!(myers(&[1], &[]), [Op::Del]);
    }
}
