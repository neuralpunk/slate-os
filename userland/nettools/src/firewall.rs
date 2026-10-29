// SPDX-License-Identifier: MIT OR Apache-2.0

//! `slate-firewall`: which inbound ports SlateOS's default-deny firewall
//! lets in (ADR 0134). The kernel loads the firewall (the nf_tables table
//! `inet slate`) at boot with nothing open; `/etc/slate/firewall` lists
//! what to open, and `slate-firewall load` (run by rc.sysinit) opens it.
//!
//! ```text
//! slate-firewall [status]          what is open (or that it is off)
//! slate-firewall allow tcp|udp PORT...   open ports, now and from now on
//! slate-firewall deny tcp|udp PORT...    close them
//! slate-firewall load              open what /etc/slate/firewall lists
//! slate-firewall off | on          take the firewall away, or bring it back
//! ```
//!
//! The file has a line per port, `allow tcp 22`, and `#` comments. Whether
//! the firewall is on is kept in /run/slate-firewall for Settings.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_net::inbound;
use slate_rt::{eprintln, fs, io, lossy, net, println, process};

pub const CONFIG: &[u8] = b"/etc/slate/firewall";
/// Whether the firewall is on (`on` or `off`), for those who can't ask
/// nf_tables (Settings): written whenever this program loads, turns on or
/// turns off the firewall.
pub const STATE: &[u8] = b"/run/slate-firewall";

fn record(on: bool) {
    let _ = fs::write_file(STATE, if on { b"on\n".as_slice() } else { b"off\n" }, 0o644);
}

const USAGE: &str = "usage: slate-firewall [status | allow tcp|udp PORT... | deny tcp|udp PORT... | load | on | off]";

/// The ports a configuration opens: (TCP, port), in order, without
/// repeats; a line it can't read is an error naming it.
pub fn parse(text: &str) -> Result<Vec<(bool, u16)>, String> {
    let mut out: Vec<(bool, u16)> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        let entry = match words.as_slice() {
            ["allow", proto, port] => proto_of(proto).zip(port.parse::<u16>().ok().filter(|p| *p != 0)),
            _ => None,
        };
        let Some(e) = entry else { return Err(format!("line {}: {line} (want `allow tcp|udp PORT`)", n + 1)) };
        if !out.contains(&e) {
            out.push(e);
        }
    }
    Ok(out)
}

fn proto_of(word: &str) -> Option<bool> {
    match word {
        "tcp" => Some(true),
        "udp" => Some(false),
        _ => None,
    }
}

/// The configuration with `ports` of one protocol opened (`allow`) or
/// closed, its other lines kept.
pub fn edit(text: &str, allow: bool, tcp: bool, ports: &[u16]) -> String {
    let proto = if tcp { "tcp" } else { "udp" };
    let mut out = String::new();
    for line in text.lines() {
        let words: Vec<&str> = line.split('#').next().unwrap_or("").split_whitespace().collect();
        let names = |p: &u16| words == ["allow", proto, &format!("{p}")];
        if !allow && ports.iter().any(names) {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if allow {
        let have = parse(&out).unwrap_or_default();
        for p in ports {
            if !have.contains(&(tcp, *p)) {
                out.push_str(&format!("allow {proto} {p}\n"));
            }
        }
    }
    out
}

/// An nf_tables socket and the answers to what is sent on it.
struct Nft {
    fd: i32,
}

impl Drop for Nft {
    fn drop(&mut self) {
        let _ = io::close(self.fd);
    }
}

impl Nft {
    fn open() -> slate_rt::Result<Nft> {
        Ok(Nft { fd: net::netfilter_socket()? })
    }

    /// Send `req`; everything that comes back until `acks`
    /// acknowledgements (or a dump's end) have.
    fn exchange(&self, req: &[u8], acks: usize) -> slate_rt::Result<Vec<u8>> {
        io::write_all(self.fd, req)?;
        let mut all = Vec::new();
        let mut buf = alloc::vec![0u8; 64 * 1024];
        let mut seen = 0;
        while seen < acks {
            let mut p = [io::PollFd { fd: self.fd, events: io::POLLIN, revents: 0 }];
            if io::poll(&mut p, 5000)? == 0 {
                return Err(slate_rt::Errno::ETIMEDOUT);
            }
            let n = net::recv(self.fd, &mut buf)?;
            let mut at = 0;
            while at + 16 <= n {
                let len = u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
                let kind = u16::from_ne_bytes([buf[at + 4], buf[at + 5]]);
                // NLMSG_ERROR (an acknowledgement or an error), NLMSG_DONE.
                if kind == 2 || kind == 3 {
                    seen += 1;
                }
                if len < 16 {
                    break;
                }
                at += len.next_multiple_of(4);
            }
            all.extend_from_slice(&buf[..n]);
        }
        Ok(all)
    }

    /// A batch, its first error.
    fn batch(&self, b: &[u8]) -> Result<(), String> {
        // Every message between the markers asks for an acknowledgement.
        let msgs = count(b).saturating_sub(2);
        let answers = self.exchange(b, msgs).map_err(|e| format!("{e}"))?;
        match inbound::first_error(&answers) {
            0 => Ok(()),
            e => Err(format!("{}", slate_rt::Errno(e))),
        }
    }

    /// The open ports of one protocol; none when the firewall is off.
    fn open_ports(&self, tcp: bool) -> Result<Option<Vec<u16>>, String> {
        let answers = self.exchange(&inbound::list(tcp), 1).map_err(|e| format!("{e}"))?;
        let (ports, on) = inbound::listed(&answers);
        if !on && inbound::first_error(&answers) == 1 {
            return Err(String::from("permission denied (run it as root)"));
        }
        Ok(on.then_some(ports))
    }
}

fn count(b: &[u8]) -> usize {
    let mut at = 0;
    let mut n = 0;
    while at + 16 <= b.len() {
        let len = u32::from_ne_bytes(b[at..at + 4].try_into().unwrap()) as usize;
        if len < 16 {
            break;
        }
        n += 1;
        at += len.next_multiple_of(4);
    }
    n
}

fn config() -> String {
    fs::read_file(CONFIG).map(|t| String::from(lossy(&t))).unwrap_or_default()
}

fn status(nft: &Nft) -> Result<(), String> {
    let (Some(tcp), Some(udp)) = (nft.open_ports(true)?, nft.open_ports(false)?) else {
        println!("firewall: off (every inbound connection comes in)");
        return Ok(());
    };
    println!("firewall: on (inbound connections refused unless open)");
    let list = |ports: &[u16]| {
        if ports.is_empty() {
            String::from("none")
        } else {
            ports.iter().map(|p| format!("{p}")).collect::<Vec<_>>().join(" ")
        }
    };
    println!("open tcp: {}", list(&tcp));
    println!("open udp: {}", list(&udp));
    Ok(())
}

/// Open or close ports now, and in the configuration.
fn change(nft: &Nft, allow: bool, proto: &str, words: &[&str]) -> Result<(), String> {
    let tcp = proto_of(proto).ok_or_else(|| format!("{proto}: not tcp or udp"))?;
    let mut ports = Vec::new();
    for w in words {
        ports.push(w.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| format!("{w}: not a port"))?);
    }
    if ports.is_empty() {
        return Err(String::from(USAGE));
    }
    nft.batch(&inbound::ports(allow, tcp, &ports))?;
    let text = edit(&config(), allow, tcp, &ports);
    let mut tmp = CONFIG.to_vec();
    tmp.extend_from_slice(b".new");
    fs::write_file(&tmp, text.as_bytes(), 0o644).map_err(|e| format!("/etc/slate/firewall: {e}"))?;
    fs::rename(&tmp, CONFIG).map_err(|e| format!("/etc/slate/firewall: {e}"))
}

/// Open what the configuration lists (closing nothing).
fn load(nft: &Nft) -> Result<(), String> {
    let entries = parse(&config()).map_err(|e| format!("/etc/slate/firewall: {e}"))?;
    if nft.open_ports(true)?.is_none() {
        record(false);
        println!("slate-firewall: the firewall is off; nothing to open");
        return Ok(());
    }
    record(true);
    for tcp in [true, false] {
        let ports: Vec<u16> = entries.iter().filter(|e| e.0 == tcp).map(|e| e.1).collect();
        if !ports.is_empty() {
            nft.batch(&inbound::ports(true, tcp, &ports))?;
        }
    }
    Ok(())
}

pub fn main() -> i32 {
    let owned: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from(lossy(a))).collect();
    let args: Vec<&str> = owned.iter().map(String::as_str).collect();
    if matches!(args.as_slice(), ["-h" | "--help" | "help"]) {
        println!("{USAGE}");
        return 0;
    }
    let changes = !matches!(args.as_slice(), [] | ["status"]);
    if changes && process::geteuid() != 0 {
        eprintln!("slate-firewall: changing the firewall needs root (su -)");
        return 1;
    }
    let nft = match Nft::open() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("slate-firewall: {e}");
            return 1;
        }
    };
    let r = match args.as_slice() {
        [] | ["status"] => status(&nft),
        ["allow", proto, ports @ ..] => change(&nft, true, proto, ports),
        ["deny", proto, ports @ ..] => change(&nft, false, proto, ports),
        ["load"] => load(&nft),
        ["off"] => nft.batch(&inbound::remove()).inspect(|()| record(false)),
        ["on"] => match nft.open_ports(true) {
            Ok(Some(_)) => {
                record(true);
                Ok(())
            }
            _ => nft.batch(&inbound::table()).and_then(|()| load(&nft)),
        },
        _ => Err(String::from(USAGE)),
    };
    match r {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("slate-firewall: {e}");
            1
        }
    }
}
