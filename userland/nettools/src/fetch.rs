// SPDX-License-Identifier: MIT OR Apache-2.0

//! `fetch [-4|-6] [-o FILE] [-c] [-P] [-q] [--ca FILE] URL...` (ADR 0052,
//! ADR 0053): an HTTP/1.1 GET (RFC 9110, RFC 9112) over IPv4 or IPv6, and
//! over TLS for `https:`, through slate-web. The body goes to standard
//! output, or to FILE (`-o -` is standard output); several URLs are
//! fetched in turn, their bodies one after another, and a later TLS
//! connection to the same host resumes the session (said unless `-q`,
//! ADR 0136); redirects are followed
//! (at most 10); bodies may be chunked. `-c` continues a FILE already
//! partly there: the rest is asked for (a Range request) and added, or the
//! whole body written again if the server sends it all; a FILE already
//! complete (416) is left as it is. `-P` shows the bytes so far (and the
//! share of the whole when the length is known) on standard error.
//! `--ca FILE` trusts the certificate authorities in FILE (PEM) too, for
//! private servers. Unless `-q`, what happened goes to standard error.
//! Exits 0 on a 2xx answer, 1 otherwise.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{eprintln, fs, io, println};
use slate_web::http::{self, Body, Got, Head, Url, UrlError};

use crate::resolve::Family;

/// Where the body goes: the file (or standard output), opened when a
/// good answer begins.
struct Sink<'a> {
    path: Option<&'a str>,
    fd: Option<i32>,
    /// `-c`: the bytes the file had, asked to continue from.
    from: u64,
    /// `-P`: show the progress.
    progress: bool,
    /// After an earlier URL's body: add to the file.
    append: bool,
    /// Bytes of the body the file has now, and its whole length if known.
    have: u64,
    total: Option<u64>,
    shown: u64,
}

/// The progress line: bytes so far, and of how many with the share.
pub fn progress_line(have: u64, total: Option<u64>) -> String {
    match total {
        Some(t) if t > 0 => format!("fetch: {have} of {t} bytes ({}%)", have.min(t) * 100 / t),
        _ => format!("fetch: {have} bytes"),
    }
}

impl Body for Sink<'_> {
    fn start(&mut self, head: &Head) -> Result<(), String> {
        // 206: the rest, after what the file has; otherwise all of it.
        let resumed = head.status == 206 && self.from > 0;
        self.have = if resumed { self.from } else { 0 };
        self.total = head.length().map(|n| n + self.have);
        if self.fd.is_none() {
            let keep = if resumed || self.append { fs::O_APPEND } else { fs::O_TRUNC };
            self.fd = Some(match self.path {
                None => 1,
                Some(p) => fs::open(p.as_bytes(), fs::O_WRONLY | fs::O_CREAT | keep, 0o644)
                    .map_err(|e| format!("{p}: {}", e.message()))?,
            });
        }
        Ok(())
    }
    fn data(&mut self, b: &[u8]) -> Result<(), String> {
        if let Some(fd) = self.fd {
            io::write_all(fd, b).map_err(|e| format!("write: {}", e.message()))?;
        }
        self.have += b.len() as u64;
        // Every 256 KiB or so, on one line.
        if self.progress && self.have - self.shown >= 256 << 10 {
            self.shown = self.have;
            slate_rt::eprint!("\r{}", progress_line(self.have, self.total));
        }
        Ok(())
    }
}

const USAGE: &str = "usage: fetch [-4|-6] [-o FILE] [-c] [-P] [-q] [--ca FILE] URL...";

pub fn main() -> i32 {
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from_utf8_lossy(a).into()).collect();
    let (mut family, mut out, mut quiet, mut urls, mut ca) = (Family::Any, None, false, Vec::new(), None::<String>);
    let (mut resume, mut progress) = (false, false);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-4" => family = Family::V4,
            "-6" => family = Family::V6,
            "-q" => quiet = true,
            "-c" | "--continue" => resume = true,
            "-P" | "--progress" => progress = true,
            "-o" | "--ca" => {
                i += 1;
                match args.get(i) {
                    Some(f) if args[i - 1] == "-o" => out = Some(f.clone()),
                    Some(f) => ca = Some(f.clone()),
                    None => {
                        eprintln!("{USAGE}");
                        return 1;
                    }
                }
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return 0;
            }
            a if a.starts_with('-') => {
                eprintln!("fetch: unknown option {a}\n{USAGE}");
                return 1;
            }
            a => urls.push(String::from(a)),
        }
        i += 1;
    }
    if urls.is_empty() {
        eprintln!("{USAGE}");
        return 1;
    }
    if resume && urls.len() > 1 {
        eprintln!("fetch: -c continues one file from one URL");
        return 1;
    }
    let ca = match &ca {
        Some(f) => match fs::read_file(f.as_bytes()) {
            Ok(d) => Some(d),
            Err(e) => {
                eprintln!("fetch: {f}: {}", e.message());
                return 1;
            }
        },
        None => None,
    };
    let mut status = 0;
    for (k, url) in urls.iter().enumerate() {
        let before = http::resumed();
        let one = fetch_one(url, (family, out.as_deref(), quiet, resume, progress, k > 0), ca.as_deref());
        if !quiet && http::resumed() > before {
            eprintln!("fetch: {url}: TLS session resumed");
        }
        status = status.max(one);
    }
    status
}

/// One URL: (family, -o, -q, -c, -P, whether a body came before), the
/// extra authorities. The exit status it earns.
fn fetch_one(
    url: &str,
    (family, out, quiet, resume, progress, append): (Family, Option<&str>, bool, bool, bool, bool),
    ca: Option<&[u8]>,
) -> i32 {
    let u = match Url::parse(url) {
        Ok(u) => u,
        Err(UrlError::Scheme) => {
            eprintln!("fetch: {url}: only http: and https: URLs can be fetched");
            return 1;
        }
        Err(UrlError::Bad) => {
            eprintln!("fetch: {url}: not a valid URL");
            return 1;
        }
    };
    let path = out.filter(|p| *p != "-");
    if resume && path.is_none() {
        eprintln!("fetch: -c continues a file: it needs -o FILE");
        return 1;
    }
    let from = match path {
        Some(p) if resume => fs::stat(p.as_bytes()).map_or(0, |s| s.size.max(0) as u64),
        _ => 0,
    };
    let mut sink = Sink { path, fd: None, from, progress, append, have: 0, total: None, shown: 0 };
    let mut redirected = |from: &Url, to: &Url| {
        if !quiet {
            eprintln!("fetch: {}: redirected to {}", from.text(), to.text());
        }
    };
    let opts = http::Opts { family, agent: "slate-fetch/0.1", ca, from };
    let r = http::get(&u, &opts, &mut sink, &mut redirected);
    if let Some(fd) = sink.fd.filter(|fd| *fd != 1) {
        let _ = io::close(fd);
    }
    if progress && sink.fd.is_some() {
        eprintln!("\r{}", progress_line(sink.have, sink.total));
    }
    match r {
        // Asked for bytes past the end: the file is whole already.
        Ok((last, Got::Status(416, _))) if from > 0 => {
            if !quiet {
                eprintln!("fetch: {}: {} is complete already", last.text(), path.unwrap_or("-"));
            }
            0
        }
        Ok((last, Got::Body(n))) => {
            if !quiet && let Some(p) = path {
                eprintln!("fetch: {}: {n} bytes to {p}", last.text());
            }
            0
        }
        Ok((last, Got::Status(code, reason))) => {
            eprintln!("fetch: {}: {code} {reason}", last.text());
            1
        }
        Err(f) => {
            eprintln!("fetch: {}: {}", f.url.text(), f.why);
            1
        }
    }
}
