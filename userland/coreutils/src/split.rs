// SPDX-License-Identifier: MIT OR Apache-2.0

//! split: cut a file into pieces by lines (`-l`), bytes (`-b`), whole
//! lines up to a size (`-C`) or a number of chunks (`-n N`, `l/N`, `r/N`,
//! `K/N`). Output names are PREFIX plus a suffix that, unless `-a` fixes
//! its length, grows by two once the first symbol would reach the last
//! one (xyz is followed by xzaaa), as GNU's split names them. `-t`
//! changes the line separator; `--filter` gives each piece to a command
//! (`$SHELL -c`, the piece's name in `$FILE`) instead of a file (ADR
//! 0148).

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, io, lossy, println};

use crate::util::{Opt, Parser, bad_option, error, missing_value, parse_num, read_input};

/// The suffix generator.
struct Names {
    alphabet: Vec<u8>,
    /// Digits of the current suffix, as indexes into `alphabet`.
    digits: Vec<usize>,
    fixed: bool,
    started: bool,
}

impl Names {
    fn new(alphabet: Vec<u8>, len: usize, fixed: bool, start: u64) -> Names {
        let mut n = Names { alphabet, digits: alloc::vec![0; len], fixed, started: false };
        let base = n.alphabet.len() as u64;
        let mut v = start;
        for d in n.digits.iter_mut().rev() {
            *d = (v % base) as usize;
            v /= base;
        }
        n
    }

    /// The next suffix, or None when a fixed length is used up.
    fn next(&mut self) -> Option<String> {
        if self.started {
            let last = self.alphabet.len() - 1;
            let mut i = self.digits.len();
            loop {
                if i == 0 {
                    return None;
                }
                i -= 1;
                if self.digits[i] < last {
                    self.digits[i] += 1;
                    break;
                }
                self.digits[i] = 0;
            }
            // Growing: when the leading free digit reaches the last symbol,
            // it stays as a marker and two more digits follow.
            let free = self.digits.iter().take_while(|&&d| d == last).count();
            if !self.fixed && free > 0 && free == self.lead() + 1 {
                let mut d = alloc::vec![last; free];
                d.extend(core::iter::repeat_n(0, self.digits.len() - free + 2));
                self.digits = d;
            }
        }
        self.started = true;
        Some(self.digits.iter().map(|&d| self.alphabet[d] as char).collect())
    }

    /// Marker digits in front of the current suffix (one per growth).
    fn lead(&self) -> usize {
        (self.digits.len().saturating_sub(2)) / 2
    }
}

enum Mode {
    Lines(u64),
    Bytes(u64),
    LineBytes(u64),
    /// `-n`: number of chunks, how (b, l, r), and the one to print (K/N).
    Chunks(u64, u8, Option<u64>),
}

struct Out {
    names: Names,
    prefix: Vec<u8>,
    extra: Vec<u8>,
    verbose: bool,
    fd: Option<i32>,
    /// `--filter`: the command, and the running one (its pid and the
    /// piece's name).
    filter: Option<Vec<u8>>,
    child: Option<(i32, Vec<u8>)>,
    /// The first failed command's status.
    failed: Option<i32>,
}

impl Out {
    fn open_next(&mut self) -> Result<(), ()> {
        self.close();
        if self.failed.is_some() {
            return Err(());
        }
        let Some(suffix) = self.names.next() else {
            error("output file suffixes exhausted");
            return Err(());
        };
        let mut name = self.prefix.clone();
        name.extend_from_slice(suffix.as_bytes());
        name.extend_from_slice(&self.extra);
        if let Some(cmd) = self.filter.clone() {
            return self.start(&cmd, name);
        }
        if self.verbose {
            println!("creating file '{}'", lossy(&name));
        }
        match fs::open(&name, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC, 0o666) {
            Ok(fd) => {
                self.fd = Some(fd);
                Ok(())
            }
            Err(e) => {
                error(format_args!("{}: {e}", lossy(&name)));
                Err(())
            }
        }
    }

    /// `--filter`: the command for piece `name`, reading a pipe.
    fn start(&mut self, cmd: &[u8], name: Vec<u8>) -> Result<(), ()> {
        let (r, w) = match slate_rt::process::pipe(fs::O_CLOEXEC) {
            Ok(p) => p,
            Err(e) => {
                error(format_args!("{e}"));
                return Err(());
            }
        };
        let shell = slate_rt::env::var(b"SHELL").filter(|s| !s.is_empty()).unwrap_or_else(|| b"/bin/sh".to_vec());
        match slate_rt::process::fork() {
            Ok(0) => {
                let _ = slate_rt::process::dup2(r, 0);
                let _ = slate_rt::signal::set(slate_rt::signal::SIGPIPE, slate_rt::signal::Disposition::Default);
                let mut env: Vec<Vec<u8>> =
                    slate_rt::env::vars().iter().filter(|v| !v.starts_with(b"FILE=")).cloned().collect();
                env.push([b"FILE=".as_slice(), &name].concat());
                let argv = [shell.clone(), b"-c".to_vec(), cmd.to_vec()];
                let e = slate_rt::process::execve(&shell, &argv, &env);
                error(format_args!("{}: {e}", lossy(&shell)));
                slate_rt::process::exit_now(127);
            }
            Ok(pid) => {
                let _ = io::close(r);
                self.fd = Some(w);
                self.child = Some((pid, name));
                Ok(())
            }
            Err(e) => {
                let _ = io::close(r);
                let _ = io::close(w);
                error(format_args!("fork: {e}"));
                Err(())
            }
        }
    }

    fn write(&mut self, b: &[u8]) -> Result<(), ()> {
        if let Some(fd) = self.fd
            && let Err(e) = io::write_all(fd, b)
        {
            // A command that stops reading takes no more of its piece.
            if self.child.is_some() && e == slate_rt::Errno::EPIPE {
                let _ = io::close(fd);
                self.fd = None;
                return Ok(());
            }
            error(format_args!("write error: {e}"));
            return Err(());
        }
        Ok(())
    }

    fn close(&mut self) {
        if let Some(fd) = self.fd.take() {
            let _ = io::close(fd);
        }
        // Wait for the command; the first that fails ends split, with its
        // status (as GNU's split does).
        if let Some((pid, name)) = self.child.take() {
            let st = slate_rt::process::wait(pid, 0).map_or(0, |(_, s)| s);
            let cmd = lossy(self.filter.as_deref().unwrap_or_default()).into_owned();
            if let Some(code) = slate_rt::process::exited(st).filter(|&c| c != 0) {
                error(format_args!("with FILE={}, exit {code} from command: {cmd}", lossy(&name)));
                self.failed.get_or_insert(code);
            } else if let Some(sig) = slate_rt::process::signaled(st).filter(|&s| s != slate_rt::signal::SIGPIPE) {
                error(format_args!(
                    "with FILE={}, signal {} from command: {cmd}",
                    lossy(&name),
                    slate_rt::signal::describe(sig)
                ));
                self.failed.get_or_insert(128 + sig);
            }
        }
    }
}

/// A size with split's suffixes (K, M, G, KB, MB, ..., b).
fn size(v: &[u8]) -> Option<u64> {
    let n = crate::od::parse_size(v)?;
    (n > 0).then_some(n)
}

/// Byte ranges of `n` chunks of `len` bytes: the first `len % n` chunks
/// get one byte more.
fn chunk_bounds(len: u64, n: u64) -> Vec<(u64, u64)> {
    let (q, r) = (len / n, len % n);
    (0..n)
        .map(|k| {
            let start = k * q + k.min(r);
            (start, start + q + u64::from(k < r))
        })
        .collect()
}

fn run(mode: &Mode, data: &[u8], out: &mut Out, elide: bool, sep: u8) -> Result<(), ()> {
    match *mode {
        Mode::Lines(n) => {
            let mut count = n;
            for line in data.split_inclusive(|&c| c == sep) {
                if count == n {
                    out.open_next()?;
                    count = 0;
                }
                out.write(line)?;
                count += 1;
            }
        }
        Mode::Bytes(n) => {
            for piece in data.chunks(n as usize) {
                out.open_next()?;
                out.write(piece)?;
            }
        }
        Mode::LineBytes(n) => {
            let n = n as usize;
            let mut used = n;
            for mut line in data.split_inclusive(|&c| c == sep) {
                while !line.is_empty() {
                    if used + line.len() <= n {
                        out.write(line)?;
                        used += line.len();
                        break;
                    }
                    if used > 0 {
                        out.open_next()?;
                        used = 0;
                        continue;
                    }
                    // A line longer than a piece is cut.
                    out.write(&line[..n])?;
                    line = &line[n..];
                    used = n;
                }
            }
        }
        Mode::Chunks(n, how, only) => {
            let bounds = chunk_bounds(data.len() as u64, n);
            let mut pieces: Vec<Vec<u8>> = alloc::vec![Vec::new(); n as usize];
            match how {
                b'b' => {
                    for (k, &(s, e)) in bounds.iter().enumerate() {
                        pieces[k].extend_from_slice(&data[s as usize..e as usize]);
                    }
                }
                b'l' => {
                    // A line goes to the chunk its first byte falls in.
                    let mut pos = 0u64;
                    let mut k = 0;
                    for line in data.split_inclusive(|&c| c == sep) {
                        while k + 1 < bounds.len() && pos >= bounds[k].1 {
                            k += 1;
                        }
                        pieces[k].extend_from_slice(line);
                        pos += line.len() as u64;
                    }
                }
                _ => {
                    for (i, line) in data.split_inclusive(|&c| c == sep).enumerate() {
                        pieces[i % n as usize].extend_from_slice(line);
                    }
                }
            }
            if let Some(k) = only {
                io::out(&pieces[k as usize - 1]);
                return Ok(());
            }
            for p in &pieces {
                if elide && p.is_empty() {
                    continue;
                }
                out.open_next()?;
                out.write(p)?;
            }
        }
    }
    Ok(())
}

pub fn main(args: &[Vec<u8>]) -> i32 {
    let mut mode = Mode::Lines(1000);
    let (mut suffix_len, mut numeric, mut start, mut verbose, mut elide) = (None::<usize>, 0u8, 0u64, false, false);
    let mut extra = Vec::new();
    let mut operands = Vec::new();
    let mut sep = b'\n';
    let mut filter: Option<Vec<u8>> = None;
    let mut p = Parser::new(args, b"lbCnadt");
    p.numeric = true;
    let bad = |what: &str, v: &[u8]| -> i32 {
        error(format_args!("invalid number of {what}: '{}'", lossy(v)));
        1
    };
    while let Some(o) = p.next() {
        let (c, long) = match &o {
            Opt::Short(c) => (*c, ""),
            Opt::Long(l) => (0, l.as_str()),
            Opt::Operand(x) => {
                operands.push(x.clone());
                continue;
            }
        };
        if c == 0 && long.bytes().all(|b| b.is_ascii_digit()) {
            // -NUM: lines.
            mode = Mode::Lines(long.parse().unwrap_or(1000));
            continue;
        }
        let name = match (c, long) {
            (b'l', _) | (_, "lines") => 'l',
            (b'b', _) | (_, "bytes") => 'b',
            (b'C', _) | (_, "line-bytes") => 'C',
            (b'n', _) | (_, "number") => 'n',
            (b'a', _) | (_, "suffix-length") => 'a',
            (_, "additional-suffix") => 's',
            (b't', _) | (_, "separator") => 't',
            (_, "filter") => 'f',
            (b'd', _) => {
                numeric = b'd';
                continue;
            }
            (b'x', _) => {
                numeric = b'x';
                continue;
            }
            (_, "numeric-suffixes" | "hex-suffixes") => {
                numeric = if long == "numeric-suffixes" { b'd' } else { b'x' };
                if let Some(v) = p.inline_value() {
                    match parse_num(&v) {
                        Some(s) => start = s,
                        None => {
                            error(format_args!("invalid start value for numerical suffix: '{}'", lossy(&v)));
                            return 1;
                        }
                    }
                }
                continue;
            }
            (b'e', _) | (_, "elide-empty-files") => {
                elide = true;
                continue;
            }
            (_, "verbose") => {
                verbose = true;
                continue;
            }
            _ => return bad_option(&o),
        };
        let Some(v) = p.value() else { return missing_value(c as char) };
        match name {
            'l' => match parse_num::<u64>(&v) {
                Some(n) if n > 0 => mode = Mode::Lines(n),
                _ => return bad("lines", &v),
            },
            'b' => match size(&v) {
                Some(n) => mode = Mode::Bytes(n),
                None => return bad("bytes", &v),
            },
            'C' => match size(&v) {
                Some(n) => mode = Mode::LineBytes(n),
                None => return bad("bytes", &v),
            },
            'a' => match parse_num::<usize>(&v) {
                Some(n) if n > 0 => suffix_len = Some(n),
                _ => {
                    error(format_args!("invalid suffix length: '{}'", lossy(&v)));
                    return 1;
                }
            },
            's' => extra = v,
            'f' => filter = Some(v),
            't' => match v.as_slice() {
                [c] => sep = *c,
                b"\\0" => sep = 0,
                [] => {
                    error("empty record separator");
                    return 1;
                }
                _ => {
                    error(format_args!("multi-character separator '{}'", lossy(&v)));
                    return 1;
                }
            },
            _ => {
                let (how, rest) = match v.split_first() {
                    Some((&h @ (b'l' | b'r'), r)) if r.first() == Some(&b'/') => (h, &r[1..]),
                    _ => (b'b', &v[..]),
                };
                let (k, n) = match rest.iter().position(|&c| c == b'/') {
                    Some(i) => (parse_num::<u64>(&rest[..i]), parse_num::<u64>(&rest[i + 1..])),
                    None => (None, parse_num::<u64>(rest)),
                };
                match n {
                    Some(n) if n > 0 && k.is_none_or(|k| k >= 1 && k <= n) => {
                        mode = Mode::Chunks(n, how, k);
                    }
                    _ => return bad("chunks", &v),
                }
            }
        }
    }
    if operands.len() > 2 {
        error(format_args!("extra operand '{}'", lossy(&operands[2])));
        return 1;
    }
    let input = operands.first().cloned().unwrap_or_else(|| b"-".to_vec());
    let prefix = operands.get(1).cloned().unwrap_or_else(|| b"x".to_vec());
    let data = match read_input(&input) {
        Ok(d) => d,
        Err(e) => {
            error(format_args!("cannot open '{}' for reading: {e}", lossy(&input)));
            return 1;
        }
    };
    let alphabet: Vec<u8> = match numeric {
        b'd' => b"0123456789".to_vec(),
        b'x' => b"0123456789abcdef".to_vec(),
        _ => (b'a'..=b'z').collect(),
    };
    let mut len = suffix_len.unwrap_or(2);
    if let Mode::Chunks(n, _, _) = mode {
        // Enough digits for every chunk.
        let mut cap = alphabet.len() as u64;
        let mut need = 1;
        while cap < n + start {
            cap = cap.saturating_mul(alphabet.len() as u64);
            need += 1;
        }
        if suffix_len.is_some_and(|l| l < need) {
            error("output file suffixes exhausted");
            return 1;
        }
        len = len.max(need);
    }
    let fixed = suffix_len.is_some() || start > 0 || matches!(mode, Mode::Chunks(..));
    if filter.is_some() {
        // A command that stops reading is not an error.
        let _ = slate_rt::signal::set(slate_rt::signal::SIGPIPE, slate_rt::signal::Disposition::Ignore);
    }
    let mut out = Out {
        names: Names::new(alphabet, len, fixed, start),
        prefix,
        extra,
        verbose,
        fd: None,
        filter,
        child: None,
        failed: None,
    };
    let r = run(&mode, &data, &mut out, elide, sep);
    out.close();
    io::flush_stdout();
    match out.failed {
        Some(code) => code,
        None => i32::from(r.is_err()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(alpha: &[u8], n: usize) -> Vec<String> {
        let mut g = Names::new(alpha.to_vec(), 2, false, 0);
        (0..n).map(|_| g.next().unwrap()).collect()
    }

    #[test]
    fn suffixes_grow() {
        let v = names(b"abcdefghijklmnopqrstuvwxyz", 700);
        assert_eq!(v[0], "aa");
        assert_eq!(v[649], "yz");
        assert_eq!(v[650], "zaaa");
        assert_eq!(v[673], "zaax");
        let d = names(b"0123456789", 120);
        assert_eq!(d[89], "89");
        assert_eq!(d[90], "9000");
        assert_eq!(d[119], "9029");
        let mut fixed = Names::new(b"ab".to_vec(), 1, true, 0);
        assert_eq!((fixed.next(), fixed.next(), fixed.next()), (Some("a".into()), Some("b".into()), None));
    }

    #[test]
    fn chunks() {
        assert_eq!(chunk_bounds(22, 3), [(0, 8), (8, 15), (15, 22)]);
        assert_eq!(chunk_bounds(3, 5)[3], (3, 3));
    }
}
