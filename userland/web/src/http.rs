// SPDX-License-Identifier: MIT OR Apache-2.0

//! An HTTP/1.1 GET (RFC 9110, RFC 9112) over IPv4 or IPv6, its body handed
//! over as it arrives (a [`Body`]), redirects followed (at most
//! [`MAX_REDIRECTS`]), chunked bodies decoded. `https:` goes over Slate's
//! TLS 1.3 client (ADR 0053), trusting the certificate authorities in
//! /etc/ssl/certs (and any the caller adds).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, io, net};

use crate::resolve::{self, Family};

pub const MAX_REDIRECTS: usize = 10;
const CONNECT_MS: i32 = 10_000;
const READ_MS: i32 = 30_000;

/// An `http:` or `https:` URL's parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    /// The path and query, from the first `/` (at least `/`).
    pub target: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UrlError {
    Scheme,
    Bad,
}

impl Url {
    pub fn parse(s: &str) -> Result<Url, UrlError> {
        let Some((scheme, rest)) = s.split_once("://") else { return Err(UrlError::Bad) };
        let https = match scheme.to_ascii_lowercase().as_str() {
            "http" => false,
            "https" => true,
            _ => return Err(UrlError::Scheme),
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        // No user information in URLs we fetch.
        if authority.contains('@') || authority.is_empty() {
            return Err(UrlError::Bad);
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, p) = v6.split_once(']').ok_or(UrlError::Bad)?;
            (h, p.strip_prefix(':'))
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            }
        };
        let port = match port {
            None | Some("") => default_port(https),
            Some(p) => p.parse().ok().filter(|p| *p != 0).ok_or(UrlError::Bad)?,
        };
        let tail = tail.split('#').next().unwrap_or("");
        let target = if tail.starts_with('/') { tail.into() } else { format!("/{tail}") };
        if host.is_empty() || target.bytes().any(|b| b <= b' ' || b == 0x7F) {
            return Err(UrlError::Bad);
        }
        Ok(Url { https, host: host.into(), port, target })
    }

    /// The Host header's value.
    pub fn authority(&self) -> String {
        let h = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == default_port(self.https) { h } else { format!("{h}:{}", self.port) }
    }

    pub fn text(&self) -> String {
        format!("{}://{}{}", if self.https { "https" } else { "http" }, self.authority(), self.target)
    }

    /// Where a Location header points, from this URL.
    pub fn join(&self, location: &str) -> Result<Url, UrlError> {
        if location.contains("://") {
            return Url::parse(location);
        }
        if let Some(rest) = location.strip_prefix("//") {
            return Url::parse(&format!("{}://{rest}", if self.https { "https" } else { "http" }));
        }
        let target = if location.starts_with('/') {
            location.into()
        } else {
            let path = self.target.split('?').next().unwrap_or("/");
            let dir = &path[..path.rfind('/').map_or(1, |i| i + 1)];
            format!("{dir}{location}")
        };
        Ok(Url { target, ..self.clone() })
    }
}

fn default_port(https: bool) -> u16 {
    if https { 443 } else { 80 }
}

/// The request, from `agent` (the User-Agent); from byte `from` of the
/// body on (a Range request, RFC 9110 §14.2) unless it is 0.
pub fn request(u: &Url, agent: &str, from: u64) -> Vec<u8> {
    let range = if from > 0 { format!("Range: bytes={from}-\r\n") } else { String::new() };
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {agent}\r\nAccept: */*\r\n\
         Accept-Encoding: identity\r\n{range}Connection: close\r\n\r\n",
        u.target,
        u.authority()
    )
    .into_bytes()
}

/// Not HTTP, or a body that breaks its framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadHttp;

/// A response's head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
}

impl Head {
    /// A header's value (names compare without case).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn chunked(&self) -> bool {
        self.get("transfer-encoding")
            .is_some_and(|v| v.rsplit(',').next().is_some_and(|l| l.trim().eq_ignore_ascii_case("chunked")))
    }

    pub fn length(&self) -> Option<u64> {
        self.get("content-length").and_then(|v| v.trim().parse().ok())
    }
}

/// Parse a head that ends at `\r\n\r\n`: (head, bytes it took). None if
/// more is needed; Err if it is not HTTP.
pub fn parse_head(b: &[u8]) -> Result<Option<(Head, usize)>, BadHttp> {
    let Some(end) = b.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if b.len() > 64 * 1024 { Err(BadHttp) } else { Ok(None) };
    };
    let text = core::str::from_utf8(&b[..end]).map_err(|_| BadHttp)?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or(BadHttp)?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().ok_or(BadHttp)?;
    if !version.starts_with("HTTP/1.") {
        return Err(BadHttp);
    }
    let status = parts.next().and_then(|s| s.parse().ok()).ok_or(BadHttp)?;
    let reason = parts.next().unwrap_or("").into();
    let mut headers = Vec::new();
    for l in lines {
        let (n, v) = l.split_once(':').ok_or(BadHttp)?;
        headers.push((n.trim().into(), v.trim().into()));
    }
    Ok(Some((Head { status, reason, headers }, end + 4)))
}

/// A chunked body being decoded (RFC 9112 §7.1): sizes in hex, optional
/// extensions after `;`, the data, CRLF; a zero size, trailers, CRLF.
#[derive(Debug, Default)]
pub struct Chunked {
    state: ChunkState,
    line: Vec<u8>,
}

#[derive(Debug, Default, PartialEq, Eq)]
enum ChunkState {
    #[default]
    Size,
    Data(u64),
    DataEnd,
    Trailers,
    Done,
}

impl Chunked {
    /// Decode `input`, passing data to `out`. Ok(true) once the body ends.
    pub fn feed(&mut self, mut input: &[u8], out: &mut dyn FnMut(&[u8])) -> Result<bool, BadHttp> {
        while !input.is_empty() && self.state != ChunkState::Done {
            if let ChunkState::Data(left) = self.state {
                let n = (left as usize).min(input.len());
                out(&input[..n]);
                input = &input[n..];
                let left = left - n as u64;
                self.state = if left == 0 { ChunkState::DataEnd } else { ChunkState::Data(left) };
                continue;
            }
            let b = input[0];
            input = &input[1..];
            if b != b'\n' {
                if self.line.len() > 4096 {
                    return Err(BadHttp);
                }
                self.line.push(b);
                continue;
            }
            let line = core::mem::take(&mut self.line);
            let line = line.strip_suffix(b"\r").unwrap_or(&line);
            self.state = match self.state {
                ChunkState::Size => {
                    let hex = line.split(|&c| c == b';').next().unwrap_or(&[]);
                    let hex = core::str::from_utf8(hex).map_err(|_| BadHttp)?.trim();
                    match u64::from_str_radix(hex, 16).map_err(|_| BadHttp)? {
                        0 => ChunkState::Trailers,
                        n => ChunkState::Data(n),
                    }
                }
                ChunkState::DataEnd if line.is_empty() => ChunkState::Size,
                ChunkState::DataEnd => return Err(BadHttp),
                ChunkState::Trailers if line.is_empty() => ChunkState::Done,
                ChunkState::Trailers => ChunkState::Trailers,
                ChunkState::Data(_) | ChunkState::Done => unreachable!(),
            };
        }
        Ok(self.state == ChunkState::Done)
    }
}

/// Where a successful answer's body goes.
pub trait Body {
    /// A 2xx answer begins (before any data, even for an empty body).
    fn start(&mut self, _head: &Head) -> Result<(), String> {
        Ok(())
    }
    /// The next bytes of the body.
    fn data(&mut self, bytes: &[u8]) -> Result<(), String>;
}

/// How a GET ended, after any redirects.
#[derive(Debug, PartialEq, Eq)]
pub enum Got {
    /// A 2xx answer: the body's length went to the [`Body`].
    Body(u64),
    /// Any other answer.
    Status(u16, String),
}

/// What went wrong: the URL concerned and why.
#[derive(Debug, PartialEq, Eq)]
pub struct Failed {
    pub url: Url,
    pub why: String,
}

/// How to fetch.
#[derive(Clone, Copy, Debug)]
pub struct Opts<'a> {
    pub family: Family,
    /// The User-Agent.
    pub agent: &'a str,
    /// Certificate authorities (PEM) to trust besides the system's.
    pub ca: Option<&'a [u8]>,
    /// Ask for the body from this byte on (0: all of it); a server that
    /// can answers 206 with the rest, else 200 with all.
    pub from: u64,
}

/// GET `url` (redirects followed; each one is told to `redirected`), the
/// body to `body`.
pub fn get(
    url: &Url,
    opts: &Opts<'_>,
    body: &mut dyn Body,
    redirected: &mut dyn FnMut(&Url, &Url),
) -> Result<(Url, Got), Failed> {
    let mut u = url.clone();
    for _ in 0..=MAX_REDIRECTS {
        let fail = |why: String| Failed { url: u.clone(), why };
        match get_once(&u, opts, body).map_err(fail)? {
            Once::Done(got) => return Ok((u, got)),
            Once::Redirect(loc) => match u.join(&loc) {
                Ok(next) => {
                    redirected(&u, &next);
                    u = next;
                }
                Err(_) => return Err(Failed { url: u, why: format!("a bad redirect: {loc}") }),
            },
        }
    }
    Err(Failed { url: u, why: "too many redirects".into() })
}

enum Once {
    Done(Got),
    Redirect(String),
}

struct Conn(i32);

impl Drop for Conn {
    fn drop(&mut self) {
        let _ = io::close(self.0);
    }
}

impl Conn {
    fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        let mut p = [io::PollFd { fd: self.0, events: io::POLLIN, revents: 0 }];
        match io::poll(&mut p, READ_MS) {
            Ok(0) => Err("timed out".into()),
            Err(e) => Err(e.message().into()),
            Ok(_) => io::read(self.0, buf).map_err(|e| e.message().into()),
        }
    }
}

fn connect(u: &Url, family: Family) -> Result<Conn, String> {
    let addrs = resolve::resolve(&u.host, family).map_err(|e| e.describe(&u.host))?;
    let mut last = String::new();
    for a in addrs {
        match net::tcp_connect_peer(&resolve::peer(a, u.port), CONNECT_MS) {
            Ok(fd) => return Ok(Conn(fd)),
            Err(e) => last = format!("{a} port {}: {}", u.port, e.message()),
        }
    }
    Err(last)
}

/// Where the system keeps its certificate authorities (ADR 0053).
pub const CERTS: &str = "/etc/ssl/certs";

/// The trusted certificate authorities: every PEM file in /etc/ssl/certs,
/// and `extra`.
pub fn roots(extra: Option<&[u8]>) -> slate_tls::x509::Roots {
    let mut r = slate_tls::x509::Roots::default();
    let mut names: Vec<Vec<u8>> =
        fs::read_dir(CERTS.as_bytes()).unwrap_or_default().into_iter().map(|e| e.name).collect();
    names.sort();
    for n in names.iter().filter(|n| n.ends_with(b".pem") || n.ends_with(b".crt")) {
        if let Ok(text) = fs::read_file(&fs::join(CERTS.as_bytes(), n)) {
            r.add_pem(&text);
        }
    }
    if let Some(e) = extra {
        r.add_pem(e);
    }
    r
}

/// Session tickets from this program's earlier TLS connections, to
/// resume their sessions (ADR 0136): each used once, the newest few kept.
static TICKETS: slate_rt::sync::Mutex<Vec<slate_tls::client::Ticket>> = slate_rt::sync::Mutex::new(Vec::new());
/// How many TLS connections resumed a session.
static RESUMED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// How many of this program's TLS connections so far resumed a session.
pub fn resumed() -> usize {
    RESUMED.load(core::sync::atomic::Ordering::Relaxed)
}

/// Keep the tickets a connection received.
fn keep_tickets(tls: &mut slate_tls::client::Client) {
    let new = tls.take_tickets();
    if new.is_empty() {
        return;
    }
    let mut all = TICKETS.lock();
    all.extend(new);
    let extra = all.len().saturating_sub(16);
    all.drain(..extra);
}

/// A connection: plain, or TLS over it.
enum Stream {
    Plain(Conn),
    Tls {
        conn: Conn,
        tls: alloc::boxed::Box<slate_tls::client::Client>,
        /// Application data read but not yet asked for.
        pending: Vec<u8>,
    },
}

impl Stream {
    fn open(u: &Url, opts: &Opts<'_>) -> Result<Stream, String> {
        let conn = connect(u, opts.family)?;
        if !u.https {
            return Ok(Stream::Plain(conn));
        }
        let roots = roots(opts.ca);
        if roots.is_empty() {
            return Err(format!("no certificate authorities in {CERTS}"));
        }
        let mut random = [0u8; 96];
        let mut spare = [0u8; 32];
        slate_rt::process::random(&mut random).map_err(|e| format!("random: {e}"))?;
        slate_rt::process::random(&mut spare).map_err(|e| format!("random: {e}"))?;
        let now = slate_rt::time::now(slate_rt::time::CLOCK_REALTIME).0;
        let host = u.host.as_str();
        let ticket = {
            let mut all = TICKETS.lock();
            all.iter().rposition(|t| t.usable(host, now)).map(|i| all.remove(i))
        };
        let tls = slate_tls::client::Client::resume(host, roots, now, random, spare, ticket)
            .map_err(|e| format!("TLS: {e}"))?;
        let mut s = Stream::Tls { conn, tls: alloc::boxed::Box::new(tls), pending: Vec::new() };
        s.handshake()?;
        Ok(s)
    }

    fn flush(conn: &Conn, tls: &mut slate_tls::client::Client) -> Result<(), String> {
        let out = tls.take_output();
        if out.is_empty() {
            return Ok(());
        }
        io::write_all(conn.0, &out).map_err(|e| format!("send: {}", e.message()))
    }

    fn handshake(&mut self) -> Result<(), String> {
        let Stream::Tls { conn, tls, .. } = self else { return Ok(()) };
        let mut buf = alloc::vec![0u8; 16 * 1024];
        while !tls.is_connected() {
            Stream::flush(conn, tls)?;
            let n = conn.read(&mut buf)?;
            if n == 0 {
                return Err("TLS: the server closed the connection during the handshake".into());
            }
            let r = tls.feed(&buf[..n]);
            // An alert we owe the server goes out before giving up.
            let _ = Stream::flush(conn, tls);
            r.map_err(|e| format!("TLS: {e}"))?;
            if tls.is_closed() {
                return Err("TLS: the server closed the connection during the handshake".into());
            }
        }
        if tls.resumed() {
            RESUMED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        Stream::flush(conn, tls)
    }

    fn send(&mut self, b: &[u8]) -> Result<(), String> {
        match self {
            Stream::Plain(c) => io::write_all(c.0, b).map_err(|e| format!("send: {}", e.message())),
            Stream::Tls { conn, tls, .. } => {
                tls.write(b).map_err(|e| format!("TLS: {e}"))?;
                Stream::flush(conn, tls)
            }
        }
    }

    /// Whether the connection ended as it should: plain, or TLS that said
    /// close_notify first (else an attacker may have cut it short).
    fn ended_cleanly(&self) -> bool {
        match self {
            Stream::Plain(_) => true,
            Stream::Tls { tls, .. } => tls.is_closed(),
        }
    }

    /// The next bytes; 0 at the end.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        match self {
            Stream::Plain(c) => c.read(buf),
            Stream::Tls { conn, tls, pending } => loop {
                pending.extend(tls.read());
                if !pending.is_empty() {
                    let n = pending.len().min(buf.len());
                    buf[..n].copy_from_slice(&pending[..n]);
                    pending.drain(..n);
                    return Ok(n);
                }
                if tls.is_closed() {
                    return Ok(0);
                }
                let n = conn.read(buf)?;
                if n == 0 {
                    return Ok(0);
                }
                let data = buf[..n].to_vec();
                let r = tls.feed(&data);
                let _ = Stream::flush(conn, tls);
                keep_tickets(tls);
                r.map_err(|e| format!("TLS: {e}"))?;
            },
        }
    }
}

fn get_once(u: &Url, opts: &Opts<'_>, body: &mut dyn Body) -> Result<Once, String> {
    let mut c = Stream::open(u, opts)?;
    c.send(&request(u, opts.agent, opts.from))?;
    let mut buf = alloc::vec![0u8; 64 * 1024];
    let mut have = Vec::new();
    let (head, used) = loop {
        let n = c.read(&mut buf)?;
        if n == 0 {
            return Err("the server closed the connection".into());
        }
        have.extend_from_slice(&buf[..n]);
        match parse_head(&have) {
            Err(BadHttp) => return Err("not an HTTP answer".into()),
            Ok(None) => continue,
            // Interim answers (100 Continue) come before the real one.
            Ok(Some((h, used))) if (100..200).contains(&h.status) => {
                have.drain(..used);
                continue;
            }
            Ok(Some(x)) => break x,
        }
    };
    let rest = have.split_off(used);
    if matches!(head.status, 301 | 302 | 303 | 307 | 308)
        && let Some(loc) = head.get("location")
    {
        return Ok(Once::Redirect(loc.into()));
    }
    if !(200..300).contains(&head.status) {
        return Ok(Once::Done(Got::Status(head.status, head.reason)));
    }
    body.start(&head)?;
    let mut total = 0u64;
    if head.chunked() {
        let mut ch = Chunked::default();
        let mut input = rest;
        loop {
            let mut failed: Option<String> = None;
            let done = ch
                .feed(&input, &mut |b| {
                    total += b.len() as u64;
                    if failed.is_none()
                        && let Err(e) = body.data(b)
                    {
                        failed = Some(e);
                    }
                })
                .map_err(|_| "a bad chunked body")?;
            if let Some(e) = failed {
                return Err(e);
            }
            if done {
                break;
            }
            let n = c.read(&mut buf)?;
            if n == 0 {
                return Err("the body was cut short".into());
            }
            input = buf[..n].to_vec();
        }
    } else {
        let want = head.length();
        let first = want.map_or(rest.len(), |w| rest.len().min(w as usize));
        body.data(&rest[..first])?;
        total += first as u64;
        while want.is_none_or(|w| total < w) {
            let n = c.read(&mut buf)?;
            if n == 0 {
                if want.is_some() {
                    return Err("the body was cut short".into());
                }
                // A body the end of the connection ends is whole only if
                // TLS ended it properly (RFC 9112 §9.8).
                if !c.ended_cleanly() {
                    return Err("the connection ended without TLS's close_notify: the body may be cut short".into());
                }
                break;
            }
            let n = want.map_or(n, |w| n.min((w - total) as usize));
            body.data(&buf[..n])?;
            total += n as u64;
        }
    }
    Ok(Once::Done(Got::Body(total)))
}
