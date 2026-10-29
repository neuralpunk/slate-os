// SPDX-License-Identifier: MIT OR Apache-2.0

//! /etc/ssh/sshd_config (ADR 0061): the keywords of sshd_config(5) that
//! apply to Slate's server, with OpenSSH's defaults. Keywords are
//! case-insensitive; the first value given for a keyword wins (as
//! sshd_config(5) says), except `Port`, `HostKey` and
//! `AuthorizedKeysFile`, which may list several. Keywords for features
//! Slate's server does not have are accepted only with their "off"
//! value; unknown keywords, `Match` and `Include` are errors.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::crypto;

pub const PATH: &str = "/etc/ssh/sshd_config";

/// PermitRootLogin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootLogin {
    Yes,
    /// Keys only (also `without-password`).
    ProhibitPassword,
    /// Keys only, and only for keys with a forced command (Slate does
    /// not run forced commands, so: no).
    ForcedCommandsOnly,
    No,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub ports: Vec<u16>,
    pub host_keys: Vec<String>,
    pub permit_root: RootLogin,
    pub password: bool,
    pub pubkey: bool,
    /// `%h`, `%u`, `%%`; relative paths are from the home directory.
    pub authorized_keys: Vec<String>,
    pub allow_users: Vec<String>,
    pub deny_users: Vec<String>,
    pub allow_groups: Vec<String>,
    pub deny_groups: Vec<String>,
    pub max_auth_tries: u32,
    /// Seconds; 0: no limit.
    pub login_grace: u32,
    pub alive_interval: u32,
    pub alive_count: u32,
    pub rekey_bytes: u64,
    /// Seconds; 0: no time limit.
    pub rekey_secs: u32,
    pub kex: Vec<&'static [u8]>,
    /// The sftp subsystem: `internal-sftp` or a program; None: none.
    pub sftp: Option<String>,
    pub banner: Option<String>,
    pub print_motd: bool,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            ports: Vec::new(),
            host_keys: Vec::new(),
            permit_root: RootLogin::ProhibitPassword,
            password: true,
            pubkey: true,
            authorized_keys: Vec::new(),
            allow_users: Vec::new(),
            deny_users: Vec::new(),
            allow_groups: Vec::new(),
            deny_groups: Vec::new(),
            max_auth_tries: 6,
            login_grace: 120,
            alive_interval: 0,
            alive_count: 3,
            rekey_bytes: 1 << 30,
            rekey_secs: 0,
            kex: KEX_ALL.to_vec(),
            sftp: Some("internal-sftp".into()),
            banner: None,
            print_motd: true,
        }
    }
}

/// The key exchange methods Slate's server has, best first.
pub const KEX_ALL: [&[u8]; 3] = [crypto::KEX_MLKEM, crypto::KEX, crypto::KEX_LIBSSH];

/// Keywords accepted only with "no" (features the server does not have).
const OFF_ONLY: [&str; 15] = [
    "usepam",
    "x11forwarding",
    "allowtcpforwarding",
    "allowagentforwarding",
    "allowstreamlocalforwarding",
    "permittunnel",
    "gatewayports",
    "permitemptypasswords",
    "permituserenvironment",
    "hostbasedauthentication",
    "kbdinteractiveauthentication",
    "challengeresponseauthentication",
    "gssapiauthentication",
    "kerberosauthentication",
    "compression",
];

/// Keywords accepted with any value and without effect here.
const NO_EFFECT: [&str; 16] = [
    "printlastlog",
    "tcpkeepalive",
    "usedns",
    "pidfile",
    "syslogfacility",
    "loglevel",
    "acceptenv",
    "strictmodes",
    "ignorerhosts",
    "addressfamily",
    "maxsessions",
    "maxstartups",
    "permittty",
    "ciphers",
    "macs",
    "hostkeyalgorithms",
];

fn yes_no(v: &str) -> Result<bool, String> {
    match v {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err(format!("expected yes or no, not {v:?}")),
    }
}

/// sshd_config(5) TIME FORMATS: `90`, `2m`, `1h30m` (s, m, h, d, w).
pub fn parse_time(v: &str) -> Result<u32, String> {
    let bad = || format!("bad time value {v:?}");
    let mut total: u64 = 0;
    let mut num = String::new();
    for c in v.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let unit: u64 = match c.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 604_800,
            _ => return Err(bad()),
        };
        total += num.parse::<u64>().map_err(|_| bad())? * unit;
        num.clear();
    }
    if !num.is_empty() {
        total += num.parse::<u64>().map_err(|_| bad())?;
    }
    if v.is_empty() {
        return Err(bad());
    }
    u32::try_from(total).map_err(|_| bad())
}

/// A size with an optional K, M or G (RekeyLimit).
fn parse_size(v: &str) -> Result<u64, String> {
    let bad = || format!("bad size {v:?}");
    let (n, mult) = match v.chars().last().map(|c| c.to_ascii_uppercase()) {
        Some('K') => (&v[..v.len() - 1], 1u64 << 10),
        Some('M') => (&v[..v.len() - 1], 1 << 20),
        Some('G') => (&v[..v.len() - 1], 1 << 30),
        _ => (v, 1),
    };
    let n: u64 = n.parse().map_err(|_| bad())?;
    // Below 16 bytes is not a limit OpenSSH accepts either.
    if n * mult < 16 {
        return Err(bad());
    }
    Ok(n * mult)
}

/// KexAlgorithms: a list, or `+list` (ours are all on already), `-list`
/// (remove) or `^list` (put first).
fn parse_kex(v: &str) -> Result<Vec<&'static [u8]>, String> {
    let (op, list) = match v.chars().next() {
        Some(c @ ('+' | '-' | '^')) => (c, &v[1..]),
        _ => (' ', v),
    };
    let mut names = Vec::new();
    for n in list.split(',') {
        match KEX_ALL.iter().find(|k| **k == n.as_bytes()) {
            Some(k) => names.push(*k),
            None if op == '-' => {}
            None => return Err(format!("unsupported key exchange method {n:?}")),
        }
    }
    let out: Vec<&'static [u8]> = match op {
        '+' => KEX_ALL.to_vec(),
        '-' => KEX_ALL.iter().copied().filter(|k| !names.contains(k)).collect(),
        '^' => names.iter().copied().chain(KEX_ALL.iter().copied().filter(|k| !names.contains(k))).collect(),
        _ => names,
    };
    if out.is_empty() {
        return Err("no key exchange methods left".into());
    }
    Ok(out)
}

/// Parse the text of a configuration file.
pub fn parse(text: &str) -> Result<Settings, String> {
    let mut s = Settings::default();
    let mut seen: Vec<String> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = |e: String| format!("line {}: {e}", n + 1);
        // `Keyword value` or `Keyword=value`.
        let (key, rest) = match line.find(|c: char| c.is_whitespace() || c == '=') {
            Some(i) => (&line[..i], line[i..].trim_start_matches(|c: char| c.is_whitespace() || c == '=')),
            None => (line, ""),
        };
        let key = key.to_ascii_lowercase();
        let rest = rest.trim();
        let args: Vec<&str> = rest.split_whitespace().collect();
        if args.is_empty() {
            return Err(at(format!("{key}: missing value")));
        }
        let v = args[0];
        let first = !seen.contains(&key);
        seen.push(key.clone());
        let lower = v.to_ascii_lowercase();
        match key.as_str() {
            "port" => s.ports.push(v.parse().ok().filter(|p| *p > 0).ok_or_else(|| at(format!("bad port {v:?}")))?),
            "hostkey" => s.host_keys.push(v.into()),
            "authorizedkeysfile" => {
                if first {
                    s.authorized_keys = args.iter().map(|a| a.to_string()).collect();
                }
            }
            "allowusers" => s.allow_users.extend(args.iter().map(|a| a.to_string())),
            "denyusers" => s.deny_users.extend(args.iter().map(|a| a.to_string())),
            "allowgroups" => s.allow_groups.extend(args.iter().map(|a| a.to_string())),
            "denygroups" => s.deny_groups.extend(args.iter().map(|a| a.to_string())),
            _ if !first => {}
            "permitrootlogin" => {
                s.permit_root = match lower.as_str() {
                    "yes" => RootLogin::Yes,
                    "prohibit-password" | "without-password" => RootLogin::ProhibitPassword,
                    "forced-commands-only" => RootLogin::ForcedCommandsOnly,
                    "no" => RootLogin::No,
                    _ => return Err(at(format!("bad PermitRootLogin value {v:?}"))),
                }
            }
            "passwordauthentication" => s.password = yes_no(&lower).map_err(at)?,
            "pubkeyauthentication" => s.pubkey = yes_no(&lower).map_err(at)?,
            "maxauthtries" => s.max_auth_tries = v.parse().map_err(|_| at(format!("bad number {v:?}")))?,
            "logingracetime" => s.login_grace = parse_time(v).map_err(at)?,
            "clientaliveinterval" => s.alive_interval = parse_time(v).map_err(at)?,
            "clientalivecountmax" => s.alive_count = v.parse().map_err(|_| at(format!("bad number {v:?}")))?,
            "rekeylimit" => {
                if lower != "default" {
                    s.rekey_bytes = if lower == "none" { u64::MAX } else { parse_size(v).map_err(at)? };
                }
                if let Some(t) = args.get(1) {
                    s.rekey_secs = if *t == "none" || *t == "default" { 0 } else { parse_time(t).map_err(at)? };
                }
            }
            "kexalgorithms" => s.kex = parse_kex(v).map_err(at)?,
            "subsystem" => {
                if v != "sftp" {
                    return Err(at(format!("unsupported subsystem {v:?}")));
                }
                let Some(prog) = args.get(1) else { return Err(at("Subsystem sftp: missing program".into())) };
                s.sftp = Some(args[1..].join(" "));
                let _ = prog;
            }
            "banner" => s.banner = (lower != "none").then(|| v.to_string()),
            "printmotd" => s.print_motd = yes_no(&lower).map_err(at)?,
            "listenaddress" => {
                if !["0.0.0.0", "::", "*"].contains(&v) {
                    return Err(at(format!("ListenAddress {v}: only all addresses (0.0.0.0) are supported")));
                }
            }
            "match" | "include" => return Err(at(format!("{key} is not supported"))),
            k if OFF_ONLY.contains(&k) => {
                if lower != "no" {
                    return Err(at(format!("{key} {v}: not supported (only \"no\")")));
                }
            }
            k if NO_EFFECT.contains(&k) => {}
            _ => return Err(at(format!("unknown keyword {key:?}"))),
        }
    }
    if s.ports.is_empty() {
        s.ports.push(22);
    }
    if s.host_keys.is_empty() {
        s.host_keys.push(crate::HOST_KEY.into());
    }
    if s.authorized_keys.is_empty() {
        s.authorized_keys = alloc::vec![".ssh/authorized_keys".into(), ".ssh/authorized_keys2".into()];
    }
    Ok(s)
}

/// `sshd -T`: the settings in effect, one `keyword value` per line, as
/// OpenSSH prints them (lower-case keywords).
pub fn dump(s: &Settings) -> String {
    let yn = |b: bool| if b { "yes" } else { "no" };
    let mut o = String::new();
    for p in &s.ports {
        o.push_str(&format!("port {p}\n"));
    }
    for k in &s.host_keys {
        o.push_str(&format!("hostkey {k}\n"));
    }
    let root = match s.permit_root {
        RootLogin::Yes => "yes",
        RootLogin::ProhibitPassword => "without-password",
        RootLogin::ForcedCommandsOnly => "forced-commands-only",
        RootLogin::No => "no",
    };
    o.push_str(&format!("permitrootlogin {root}\n"));
    o.push_str(&format!("passwordauthentication {}\n", yn(s.password)));
    o.push_str(&format!("pubkeyauthentication {}\n", yn(s.pubkey)));
    o.push_str(&format!("authorizedkeysfile {}\n", s.authorized_keys.join(" ")));
    for (k, v) in [
        ("allowusers", &s.allow_users),
        ("denyusers", &s.deny_users),
        ("allowgroups", &s.allow_groups),
        ("denygroups", &s.deny_groups),
    ] {
        if !v.is_empty() {
            o.push_str(&format!("{k} {}\n", v.join(" ")));
        }
    }
    o.push_str(&format!("maxauthtries {}\n", s.max_auth_tries));
    o.push_str(&format!("logingracetime {}\n", s.login_grace));
    o.push_str(&format!("clientaliveinterval {}\n", s.alive_interval));
    o.push_str(&format!("clientalivecountmax {}\n", s.alive_count));
    let bytes = if s.rekey_bytes == u64::MAX { String::from("none") } else { format!("{}", s.rekey_bytes) };
    o.push_str(&format!("rekeylimit {bytes} {}\n", s.rekey_secs));
    let kex: Vec<String> = s.kex.iter().map(|k| String::from_utf8_lossy(k).into_owned()).collect();
    o.push_str(&format!("kexalgorithms {}\n", kex.join(",")));
    if let Some(p) = &s.sftp {
        o.push_str(&format!("subsystem sftp {p}\n"));
    }
    o.push_str(&format!("banner {}\n", s.banner.as_deref().unwrap_or("none")));
    o.push_str(&format!("printmotd {}\n", yn(s.print_motd)));
    o
}

/// A user@host pattern list entry against a user name (`*` and `?`); an
/// entry with a host part other than `*` cannot be checked here: it
/// matches for Deny (refusing) and not for Allow.
fn pattern_match(p: &[u8], s: &[u8]) -> bool {
    match (p.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => pattern_match(&p[1..], s) || (!s.is_empty() && pattern_match(p, &s[1..])),
        (Some(b'?'), Some(_)) => pattern_match(&p[1..], &s[1..]),
        (Some(a), Some(b)) if a == b => pattern_match(&p[1..], &s[1..]),
        _ => false,
    }
}

fn entry_matches(entry: &str, name: &str, deny: bool) -> bool {
    let (user, host) = entry.split_once('@').unwrap_or((entry, "*"));
    pattern_match(user.as_bytes(), name.as_bytes()) && (host == "*" || deny)
}

/// Whether AllowUsers/DenyUsers/AllowGroups/DenyGroups let `user` (with
/// these group names) log in, in sshd_config(5)'s order.
pub fn user_allowed(s: &Settings, user: &str, groups: &[String]) -> bool {
    if s.deny_users.iter().any(|e| entry_matches(e, user, true)) {
        return false;
    }
    if !s.allow_users.is_empty() && !s.allow_users.iter().any(|e| entry_matches(e, user, false)) {
        return false;
    }
    let any_group =
        |list: &[String]| list.iter().any(|p| groups.iter().any(|g| pattern_match(p.as_bytes(), g.as_bytes())));
    if any_group(&s.deny_groups) {
        return false;
    }
    s.allow_groups.is_empty() || any_group(&s.allow_groups)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_values() {
        let s = parse("# comment\n\nPort 2222\nport=2223\nPermitRootLogin no\nPasswordAuthentication no\n").unwrap();
        assert_eq!(s.ports, [2222, 2223]);
        assert_eq!(s.permit_root, RootLogin::No);
        assert!(!s.password && s.pubkey);
        assert_eq!(s.max_auth_tries, 6);
        assert_eq!(s.authorized_keys, [".ssh/authorized_keys", ".ssh/authorized_keys2"]);
        let d = parse("").unwrap();
        assert_eq!(d.ports, [22]);
        assert_eq!(d.permit_root, RootLogin::ProhibitPassword);
        assert_eq!(d.kex[0], crypto::KEX_MLKEM);
        // The first value wins.
        assert_eq!(parse("MaxAuthTries 3\nMaxAuthTries 9\n").unwrap().max_auth_tries, 3);
    }

    #[test]
    fn times_sizes_lists() {
        assert_eq!(parse_time("90"), Ok(90));
        assert_eq!(parse_time("1h30m"), Ok(5400));
        assert_eq!(parse_time("2m10s"), Ok(130));
        assert!(parse_time("3x").is_err());
        let s = parse("RekeyLimit 64K 10m\nClientAliveInterval 15\nClientAliveCountMax 2\n").unwrap();
        assert_eq!((s.rekey_bytes, s.rekey_secs, s.alive_interval, s.alive_count), (65536, 600, 15, 2));
        assert_eq!(parse("KexAlgorithms curve25519-sha256\n").unwrap().kex, [crypto::KEX]);
        assert_eq!(parse("KexAlgorithms -mlkem768x25519-sha256\n").unwrap().kex, [crypto::KEX, crypto::KEX_LIBSSH]);
        assert!(parse("KexAlgorithms diffie-hellman-group14-sha256\n").is_err());
        assert_eq!(
            parse("Subsystem sftp /usr/lib/sftp-server -l INFO\n").unwrap().sftp.as_deref(),
            Some("/usr/lib/sftp-server -l INFO")
        );
        assert_eq!(
            parse("AuthorizedKeysFile /etc/keys/%u .ssh/k\n").unwrap().authorized_keys,
            ["/etc/keys/%u", ".ssh/k"]
        );
    }

    #[test]
    fn refusals() {
        assert!(parse("X11Forwarding no\nUsePAM no\nLogLevel VERBOSE\n").is_ok());
        assert!(parse("X11Forwarding yes\n").unwrap_err().contains("line 1"));
        assert!(parse("Match User bob\n").is_err());
        assert!(parse("Include /etc/ssh/sshd_config.d/*.conf\n").is_err());
        assert!(parse("Bogus 1\n").unwrap_err().contains("unknown keyword"));
        assert!(parse("Port\n").is_err());
        assert!(parse("ListenAddress 10.0.0.1\n").is_err());
    }

    #[test]
    fn allow_and_deny() {
        let g = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let s = parse("AllowUsers ad* bob@10.0.0.1\nDenyGroups banned\n").unwrap();
        assert!(user_allowed(&s, "ada", &g(&["users"])));
        // A host-restricted Allow entry cannot be checked: no.
        assert!(!user_allowed(&s, "bob", &g(&["users"])));
        assert!(!user_allowed(&s, "adam", &g(&["banned"])));
        let d = parse("DenyUsers root@somewhere\nAllowGroups wheel\n").unwrap();
        assert!(!user_allowed(&d, "root", &g(&["wheel"])));
        assert!(user_allowed(&d, "ada", &g(&["wheel", "users"])));
        assert!(!user_allowed(&d, "carl", &g(&["users"])));
        assert!(user_allowed(&parse("").unwrap(), "anyone", &[]));
    }

    #[test]
    fn dump_round_trips() {
        let s = parse("Port 2200\nRekeyLimit 1M\nBanner /etc/issue.net\n").unwrap();
        let again = parse(
            &dump(&s).replace("without-password", "prohibit-password").replace("rekeylimit 1048576 0", "rekeylimit 1M"),
        );
        assert_eq!(again.unwrap(), s);
    }
}
