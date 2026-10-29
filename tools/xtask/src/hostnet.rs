// SPDX-License-Identifier: MIT OR Apache-2.0

//! Servers on the host for the guest's network tests. QEMU's user-mode
//! network shows the host's loopback to the guest as 10.0.2.2; the ports
//! go on the kernel command line (`slate.echo=`, `slate.tcpecho=`,
//! `slate.http=`, `slate.httpmd5=`).

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::Result;

/// Size of the file the HTTP server serves.
const HTTP_BODY: usize = 3 << 20;

pub struct HostServers {
    pub cmdline: String,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

fn body() -> Vec<u8> {
    let mut x = 0x1234_5678u32;
    (0..HTTP_BODY)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// Accept connections until `stop`, handling each on its own thread.
/// Listeners on a free port of 127.0.0.1 and, where the host has IPv6,
/// the same port of ::1: QEMU's user network takes the guest's
/// connections to its host addresses (10.0.2.2, fec0::2) to those.
fn listeners(what: &str) -> Result<(Vec<TcpListener>, u16)> {
    let v4 = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("{what}: {e}"))?;
    let port = v4.local_addr().map_err(|e| e.to_string())?.port();
    let mut all = vec![v4];
    if let Ok(v6) = TcpListener::bind(("::1", port)) {
        all.push(v6);
    }
    Ok((all, port))
}

fn serve_tcp(
    ls: Vec<TcpListener>,
    stop: Arc<AtomicBool>,
    handle: impl Fn(std::net::TcpStream) + Send + Sync + 'static,
) -> JoinHandle<()> {
    for l in &ls {
        l.set_nonblocking(true).expect("nonblocking listener");
    }
    let handle = Arc::new(handle);
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let mut idle = true;
            for l in &ls {
                if let Ok((s, _)) = l.accept() {
                    idle = false;
                    let _ = s.set_nonblocking(false);
                    let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
                    let h = handle.clone();
                    std::thread::spawn(move || h(s));
                }
            }
            if idle {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    })
}

fn echo(mut s: std::net::TcpStream) {
    let mut buf = [0u8; 65536];
    while let Ok(n) = s.read(&mut buf) {
        if n == 0 || s.write_all(&buf[..n]).is_err() {
            break;
        }
    }
}

/// Read an HTTP request's head; returns the request line.
fn read_request(s: &mut std::net::TcpStream) -> Option<String> {
    read_head(s).and_then(|h| h.lines().next().map(str::to_string))
}

/// Read an HTTP request's head, all of it.
fn read_head(s: &mut std::net::TcpStream) -> Option<String> {
    let mut req = Vec::new();
    let mut buf = [0u8; 4096];
    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => req.extend_from_slice(&buf[..n]),
        }
    }
    Some(String::from_utf8_lossy(&req).into_owned())
}

/// The start a `Range: bytes=N-` header in the request head `req` asks
/// for (RFC 9110 §14.2), if any.
fn range_from(req: &str) -> Option<usize> {
    req.lines()
        .find_map(|l| l.split_once(':').filter(|(n, _)| n.trim().eq_ignore_ascii_case("range")).map(|(_, v)| v.trim()))?
        .strip_prefix("bytes=")?
        .strip_suffix('-')?
        .parse()
        .ok()
}

fn http(mut s: std::net::TcpStream) {
    let Some(req) = read_head(&mut s) else { return };
    let b = body();
    // /redirect sends the client to /file; /chunked sends the body in
    // chunks of varying size (RFC 9112 §7.1); everything else is the body,
    // or the part a `Range: bytes=N-` asks for (206; 416 past its end).
    if req.starts_with("GET /redirect ") {
        let _ = s.write_all(b"HTTP/1.1 302 Found\r\nLocation: /file\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    if req.starts_with("GET /chunked ") {
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        let (mut at, mut n) = (0, 1);
        while at < b.len() {
            let end = (at + n).min(b.len());
            let _ = s.write_all(format!("{:x};x=y\r\n", end - at).as_bytes());
            let _ = s.write_all(&b[at..end]);
            let _ = s.write_all(b"\r\n");
            at = end;
            n = n * 7 % 9973 + 1;
        }
        let _ = s.write_all(b"0\r\nX-Trailer: 1\r\n\r\n");
        return;
    }
    if let Some(from) = range_from(&req) {
        if from >= b.len() {
            let _ = s.write_all(
                format!("HTTP/1.0 416 Range Not Satisfiable\r\nContent-Range: bytes */{}\r\n\r\n", b.len()).as_bytes(),
            );
            return;
        }
        let head = format!(
            "HTTP/1.0 206 Partial Content\r\nContent-Range: bytes {from}-{}/{}\r\nContent-Length: {}\r\n\r\n",
            b.len() - 1,
            b.len(),
            b.len() - from
        );
        let _ = s.write_all(head.as_bytes());
        let _ = s.write_all(&b[from..]);
        return;
    }
    let head =
        format!("HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", b.len());
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(&b);
}

impl HostServers {
    pub fn start() -> Result<HostServers> {
        let stop = Arc::new(AtomicBool::new(false));
        let udp = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("echo server: {e}"))?;
        let udp_port = udp.local_addr().map_err(|e| e.to_string())?.port();
        let mut udps = vec![udp];
        if let Ok(v6) = UdpSocket::bind(("::1", udp_port)) {
            udps.push(v6);
        }
        let mut threads = Vec::new();
        for udp in udps {
            udp.set_read_timeout(Some(Duration::from_millis(200))).map_err(|e| e.to_string())?;
            let s = stop.clone();
            threads.push(std::thread::spawn(move || {
                let mut buf = [0u8; 65536];
                while !s.load(Ordering::Relaxed) {
                    if let Ok((n, from)) = udp.recv_from(&mut buf) {
                        let _ = udp.send_to(&buf[..n], from);
                    }
                }
            }));
        }
        let (tcp, tcp_port) = listeners("tcp echo server")?;
        threads.push(serve_tcp(tcp, stop.clone(), echo));
        let (web, http_port) = listeners("http server")?;
        threads.push(serve_tcp(web, stop.clone(), http));
        let md5 = crate::ext4img::md5(&body())?;
        let cmdline =
            format!("slate.echo={udp_port} slate.tcpecho={tcp_port} slate.http={http_port} slate.httpmd5={md5}");
        Ok(HostServers { cmdline, stop, threads })
    }

    pub fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        for t in self.threads {
            let _ = t.join();
        }
    }
}

/// A static file server for a directory (GET only, one request per
/// connection): enough for git's "dumb" HTTP protocol (ADR 0024).
pub struct StaticServer {
    pub port: u16,
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

impl StaticServer {
    pub fn start(root: std::path::PathBuf) -> Result<StaticServer> {
        let (l, port) = listeners("static server")?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread = serve_tcp(l, stop.clone(), move |mut s| {
            let Some(line) = read_request(&mut s) else { return };
            let mut parts = line.split_whitespace();
            let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or("/"));
            let path = target.split('?').next().unwrap_or("/").trim_start_matches('/');
            let file = (method == "GET" && !path.split('/').any(|c| c == ".."))
                .then(|| std::fs::read(root.join(path)).ok())
                .flatten();
            let _ = match file {
                Some(data) => s
                    .write_all(
                        format!(
                            "HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                            data.len()
                        )
                        .as_bytes(),
                    )
                    .and_then(|()| s.write_all(&data)),
                None => s.write_all(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n"),
            };
        });
        Ok(StaticServer { port, stop, thread })
    }

    pub fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.thread.join();
    }
}

/// A UDP server on a free port of 127.0.0.1 (and ::1) answering each
/// datagram with what `answer` makes of it: xtask's DNS zone and SNTP.
pub struct UdpServer {
    pub port: u16,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

/// The reply to one query.
pub fn dns_answer(query: &[u8]) -> Option<Vec<u8>> {
    let q = slate_dns::question(query).ok()?;
    let name = String::from_utf8_lossy(&q.name).into_owned();
    if name != "slate.test" && !name.ends_with(".slate.test") {
        return slate_dns::reply(query, 3, &[]).ok();
    }
    let v6 = [0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let answers: Vec<(u16, &[u8], u32)> = match q.qtype {
        slate_dns::TYPE_A => vec![(slate_dns::TYPE_A, &[10, 0, 2, 2], 60)],
        slate_dns::TYPE_AAAA => vec![(slate_dns::TYPE_AAAA, &v6, 60)],
        _ => vec![],
    };
    slate_dns::reply(query, 0, &answers).ok()
}

/// An SNTP server's reply (RFC 4330 §5) with the host's clock: version 4,
/// mode 4, stratum 2, the request's transmit time as originate.
pub fn sntp_answer(req: &[u8]) -> Option<Vec<u8>> {
    if req.len() < 48 || req[0] & 7 != 3 {
        return None;
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?;
    let ntp = (now.as_secs() + 2_208_988_800) << 32 | ((u64::from(now.subsec_nanos()) << 32) / 1_000_000_000);
    let mut p = vec![0u8; 48];
    p[0] = 0x24;
    p[1] = 2;
    p[2] = req[2];
    p[3] = 0xEC; // precision: about 60 ns
    p[12..16].copy_from_slice(b"SLAT");
    p[16..24].copy_from_slice(&ntp.to_be_bytes());
    p[24..32].copy_from_slice(&req[40..48]);
    p[32..40].copy_from_slice(&ntp.to_be_bytes());
    p[40..48].copy_from_slice(&ntp.to_be_bytes());
    Some(p)
}

impl UdpServer {
    /// xtask's DNS zone for the tests (ADR 0052): names under `slate.test`
    /// have the host's addresses as the guest sees them, 10.0.2.2 and
    /// fec0::2; every other name does not exist.
    pub fn dns() -> Result<UdpServer> {
        UdpServer::start("dns server", dns_answer)
    }

    /// An SNTP server with the host's time.
    pub fn sntp() -> Result<UdpServer> {
        UdpServer::start("sntp server", sntp_answer)
    }

    fn start(what: &str, answer: fn(&[u8]) -> Option<Vec<u8>>) -> Result<UdpServer> {
        let v4 = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("{what}: {e}"))?;
        let port = v4.local_addr().map_err(|e| e.to_string())?.port();
        let mut socks = vec![v4];
        if let Ok(v6) = UdpSocket::bind(("::1", port)) {
            socks.push(v6);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        for sock in socks {
            sock.set_read_timeout(Some(Duration::from_millis(200))).map_err(|e| e.to_string())?;
            let s = stop.clone();
            threads.push(std::thread::spawn(move || {
                let mut buf = [0u8; 1500];
                while !s.load(Ordering::Relaxed) {
                    if let Ok((n, from)) = sock.recv_from(&mut buf)
                        && let Some(r) = answer(&buf[..n])
                    {
                        let _ = sock.send_to(&r, from);
                    }
                }
            }));
        }
        Ok(UdpServer { port, stop, threads })
    }

    pub fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        for t in self.threads {
            let _ = t.join();
        }
    }
}

/// A TCP sink for the guest's sends (tests/user/netsend.c): it reads one
/// connection to its end, checks that byte i is i mod 251, and says how
/// many bytes came and whether they all were right.
pub struct TcpSink {
    pub port: u16,
    result: std::sync::mpsc::Receiver<(u64, bool)>,
    thread: JoinHandle<()>,
}

impl TcpSink {
    pub fn start() -> Result<TcpSink> {
        let l = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("sink: {e}"))?;
        let port = l.local_addr().map_err(|e| e.to_string())?.port();
        let (tx, result) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let Ok((mut s, _)) = l.accept() else { return };
            let _ = s.set_read_timeout(Some(Duration::from_secs(120)));
            let (mut n, mut ok) = (0u64, true);
            let mut buf = vec![0u8; 1 << 16];
            loop {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(k) => {
                        for &b in &buf[..k] {
                            ok &= u64::from(b) == n % 251;
                            n += 1;
                        }
                    }
                }
            }
            let _ = tx.send((n, ok));
        });
        Ok(TcpSink { port, result, thread })
    }

    /// Bytes received and whether every one was right, once the sender
    /// has finished.
    pub fn finish(self) -> Option<(u64, bool)> {
        let r = self.result.recv_timeout(Duration::from_secs(30)).ok();
        let _ = self.thread.join();
        r
    }
}
