// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate's TLS client against the host's OpenSSL server, on the host
//! (ADR 0053, ADR 0135): `fetch` (built for Slate, run on the host as our
//! programs can be) fetches over HTTPS from `openssl s_server` with each
//! kind of server key, each cipher suite, a HelloRetryRequest, a chain
//! through an intermediate, and TLS 1.2 (RSA and ECDSA, each AEAD suite, a
//! certificate request); a second connection resumes the first's session
//! with its ticket (ADR 0136), and a server without tickets still serves;
//! a server that changes its keys mid-body (KeyUpdate) is followed; and it
//! must refuse a body cut short without close_notify, the wrong name, an expired
//! certificate, an unknown authority, a server that insists on a client
//! certificate, and TLS 1.2 with only CBC suites. Part of `cargo xtask check`; skipped when the host
//! has no OpenSSL. The certificates are made fresh in target/tls-interop.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::{Result, target_dir};

fn openssl(dir: &Path, args: &[&str]) -> Result {
    let out = Command::new("openssl").args(args).current_dir(dir).output().map_err(|e| format!("openssl: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("openssl {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr)))
    }
}

/// A key: the `openssl req -newkey` argument.
fn newkey(kind: &str) -> Vec<&str> {
    match kind {
        "rsa" => vec!["-newkey", "rsa:2048"],
        "p256" => vec!["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
        "p384" => vec!["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"],
        _ => vec!["-newkey", "ed25519"],
    }
}

/// A self-signed authority `name` with a `kind` key.
pub fn authority(dir: &Path, name: &str, kind: &str) -> Result {
    let mut a = vec!["req", "-x509"];
    a.extend(newkey(kind));
    let (key, pem, subj) = (format!("{name}.key"), format!("{name}.pem"), format!("/CN=Slate test {name}"));
    a.extend([
        "-nodes",
        "-keyout",
        &key,
        "-out",
        &pem,
        "-days",
        "30",
        "-subj",
        &subj,
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ]);
    openssl(dir, &a)
}

/// A certificate `name` with a `kind` key, signed by authority `ca`, with
/// `ext` (openssl x509 extension lines) and `dates` (x509 arguments).
pub fn issue(dir: &Path, name: &str, kind: &str, ca: &str, ext: &str, dates: &[&str]) -> Result {
    let mut a = vec!["req"];
    a.extend(newkey(kind));
    let (key, csr, pem) = (format!("{name}.key"), format!("{name}.csr"), format!("{name}.pem"));
    a.extend(["-nodes", "-keyout", &key, "-out", &csr, "-subj", "/CN=Slate test server"]);
    openssl(dir, &a)?;
    let cnf = format!("{name}.cnf");
    std::fs::write(dir.join(&cnf), ext).map_err(|e| e.to_string())?;
    let (cap, cak) = (format!("{ca}.pem"), format!("{ca}.key"));
    let mut x = vec!["x509", "-req", "-in", &csr, "-CA", &cap, "-CAkey", &cak, "-CAcreateserial", "-out", &pem];
    x.extend(["-extfile", &cnf]);
    if dates.is_empty() {
        x.extend(["-days", "10"]);
    } else {
        x.extend(dates);
    }
    openssl(dir, &x)
}

const SERVER_EXT: &str = "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n";

pub struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> Result<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    Ok(l.local_addr().map_err(|e| e.to_string())?.port())
}

/// An OCSP response about certificate `cert` from authority `issuer`,
/// signed by `signer`, saying it is good or revoked, as `out` (the
/// responder's index made for it: `openssl ocsp` wants one).
fn ocsp_response(dir: &Path, cert: &str, issuer: &str, signer: &str, revoked: bool, out: &str) -> Result {
    let field = |opt: &str| -> Result<String> {
        let o = Command::new("openssl")
            .args(["x509", "-in", &format!("{cert}.pem"), "-noout", opt, "-nameopt", "compat"])
            .current_dir(dir)
            .output()
            .map_err(|e| format!("openssl: {e}"))?;
        let t = String::from_utf8_lossy(&o.stdout).trim().to_string();
        Ok(t.split_once('=').map(|(_, v)| v.to_string()).unwrap_or(t))
    };
    let (serial, subject) = (field("-serial")?, field("-subject")?);
    // The index's dates are YYMMDDHHMMSSZ; far enough ahead is enough.
    let line = if revoked {
        format!(
            "R	491231235959Z	240101000000Z	{serial}	unknown	{subject}
"
        )
    } else {
        format!(
            "V	491231235959Z		{serial}	unknown	{subject}
"
        )
    };
    let index = format!("{out}.index");
    std::fs::write(dir.join(&index), line).map_err(|e| e.to_string())?;
    let (spem, skey, ipem) = (format!("{signer}.pem"), format!("{signer}.key"), format!("{issuer}.pem"));
    openssl(
        dir,
        &[
            "ocsp",
            "-index",
            &index,
            "-rsigner",
            &spem,
            "-rkey",
            &skey,
            "-CA",
            &ipem,
            "-issuer",
            &ipem,
            "-cert",
            &format!("{cert}.pem"),
            "-respout",
            out,
            "-ndays",
            "1",
        ],
    )
}

/// `openssl s_server` serving `dir`'s files with certificate `cert` (and
/// `extra` arguments), once it listens.
pub fn serve(dir: &Path, cert: impl AsRef<Path>, extra: &[&str]) -> Result<(Server, u16)> {
    let port = free_port()?;
    // TLS 1.3 unless the arguments ask for 1.2.
    let version = if extra.contains(&"-tls1_2") { None } else { Some("-tls1_3") };
    let child = Command::new("timeout")
        .args(["3600", "openssl", "s_server", "-quiet", "-WWW"])
        .args(version)
        .arg("-accept")
        .arg(port.to_string())
        .arg("-cert")
        .arg(cert.as_ref())
        .arg("-key")
        .arg(cert.as_ref().with_extension("key"))
        .args(extra)
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("openssl s_server: {e}"))?;
    let s = Server(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok((s, port));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err("openssl s_server did not start".into())
}

/// `openssl s_server` steered through its standard input: an HTTP answer
/// with no length, a KeyUpdate asking for ours (`K`), more body, then the
/// server killed, so the connection ends without close_notify. Our
/// fetch's (exit status, standard error, body). (A body ended properly is
/// every `-WWW` case's: their answers have no length either.)
fn steered(dir: &Path, fetch_bin: &Path) -> Result<(bool, String, Vec<u8>)> {
    use std::io::Write;
    let port = free_port()?;
    let mut child = Command::new("timeout")
        .args(["60", "openssl", "s_server", "-tls1_3", "-accept"])
        .arg(port.to_string())
        .args(["-cert", "srv-p256.pem", "-key", "srv-p256.key"])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("openssl s_server: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        if Instant::now() > deadline {
            let _ = child.kill();
            return Err("openssl s_server did not start".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // That probe was a connection of its own: s_server serves one at a
    // time and drops it, so the fetch is the next.
    let out = dir.join("steered");
    let _ = std::fs::remove_file(&out);
    let (f, ca, o) = (fetch_bin.to_path_buf(), dir.join("ca-p256.pem"), out.clone());
    let url = format!("https://localhost:{port}/");
    let fetching = std::thread::spawn(move || {
        Command::new("/bin/sh")
            .arg("-c")
            .arg("ulimit -v 1048576; exec timeout 30 \"$0\" --ca \"$1\" -o \"$2\" \"$3\"")
            .arg(f)
            .arg(ca)
            .arg(o)
            .arg(url)
            .output()
    });
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let pause = || std::thread::sleep(Duration::from_millis(700));
    pause();
    let mut say = |s: &str| {
        let _ = stdin.write_all(s.as_bytes());
        let _ = stdin.flush();
        pause();
    };
    say("HTTP/1.0 200 OK\r\n\r\npart one\n");
    say("K\n");
    say("part two\n");
    let _ = child.kill();
    let r = fetching.join().map_err(|_| "fetch thread")?.map_err(|e| format!("fetch: {e}"))?;
    let _ = child.kill();
    let _ = child.wait();
    let body = std::fs::read(&out).unwrap_or_default();
    Ok((r.status.success(), String::from_utf8_lossy(&r.stderr).into_owned(), body))
}

/// Our fetch of `url`, trusting `ca`: (exit status, standard error).
fn fetch(fetch: &Path, ca: &Path, url: &str, out: &Path) -> Result<(bool, String)> {
    let o = Command::new("/bin/sh")
        .arg("-c")
        .arg("ulimit -v 1048576; exec timeout 30 \"$0\" -q --ca \"$1\" -o \"$2\" \"$3\"")
        .arg(fetch)
        .arg(ca)
        .arg(out)
        .arg(url)
        .output()
        .map_err(|e| format!("fetch: {e}"))?;
    Ok((o.status.success(), String::from_utf8_lossy(&o.stderr).into_owned()))
}

pub fn interop() -> Result {
    if Command::new("openssl").arg("version").output().is_err() {
        println!("xtask: TLS interop skipped (no OpenSSL on the host)");
        return Ok(());
    }
    let started = Instant::now();
    let fetch_bin: PathBuf = crate::userland::symbols_dir().join("fetch");
    let dir = target_dir().join("tls-interop");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // A body big enough for many records.
    let body: Vec<u8> = (0..3_000_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect();
    std::fs::write(dir.join("big"), &body).map_err(|e| e.to_string())?;
    // Authorities and servers: one per key kind.
    for kind in ["rsa", "p256", "p384", "ed25519"] {
        authority(&dir, &format!("ca-{kind}"), kind)?;
        issue(&dir, &format!("srv-{kind}"), kind, &format!("ca-{kind}"), SERVER_EXT, &[])?;
    }
    // A chain: root, intermediate, server.
    authority(&dir, "root", "p256")?;
    issue(&dir, "inter", "p256", "root", "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n", &[])?;
    issue(&dir, "leaf", "p256", "inter", SERVER_EXT, &[])?;
    // The wrong name, and one that expired long ago.
    issue(&dir, "other", "p256", "ca-p256", "subjectAltName=DNS:other.example\n", &[])?;
    issue(
        &dir,
        "old",
        "p256",
        "ca-p256",
        SERVER_EXT,
        &["-not_before", "20200101000000Z", "-not_after", "20200102000000Z"],
    )?;
    // Name constraints (RFC 5280 §4.2.1.10): intermediates that permit
    // localhost, permit only another domain, and exclude localhost.
    for (name, rule) in [
        ("nc-ok", "permitted;DNS:localhost,permitted;IP:127.0.0.1/255.255.255.255"),
        ("nc-other", "permitted;DNS:example.org"),
        ("nc-excluded", "excluded;DNS:localhost"),
    ] {
        let ext = format!(
            "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\nnameConstraints=critical,{rule}\n"
        );
        issue(&dir, name, "p256", "root", &ext, &[])?;
        issue(&dir, &format!("{name}-leaf"), "p256", name, SERVER_EXT, &[])?;
    }
    // Stapled OCSP statuses (ADR 0137): good, revoked, and one an
    // unrelated authority signed; a must-staple certificate.
    issue(&dir, "staple", "p256", "ca-p256", &format!("{SERVER_EXT}tlsfeature=status_request\n"), &[])?;
    ocsp_response(&dir, "srv-p256", "ca-p256", "ca-p256", false, "ocsp-good.der")?;
    ocsp_response(&dir, "srv-p256", "ca-p256", "ca-p256", true, "ocsp-revoked.der")?;
    ocsp_response(&dir, "srv-p256", "ca-p256", "ca-rsa", false, "ocsp-stranger.der")?;
    ocsp_response(&dir, "staple", "ca-p256", "ca-p256", false, "ocsp-staple.der")?;
    let out = dir.join("got");
    let mut done = Vec::new();
    // What must work.
    let good: &[(&str, &str, &str, &[&str])] = &[
        ("an RSA key (PSS signatures)", "srv-rsa", "ca-rsa", &[]),
        ("a P-256 key", "srv-p256", "ca-p256", &[]),
        ("a P-384 key", "srv-p384", "ca-p384", &[]),
        ("an Ed25519 key", "srv-ed25519", "ca-ed25519", &[]),
        ("AES-256-GCM", "srv-p256", "ca-p256", &["-ciphersuites", "TLS_AES_256_GCM_SHA384"]),
        ("ChaCha20-Poly1305", "srv-p256", "ca-p256", &["-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256"]),
        ("a HelloRetryRequest (P-256 only)", "srv-p256", "ca-p256", &["-groups", "P-256"]),
        ("a HelloRetryRequest (P-384 only)", "srv-p256", "ca-p256", &["-groups", "P-384"]),
        ("a chain through an intermediate", "leaf", "root", &["-cert_chain", "inter.pem"]),
        ("TLS 1.2 with an RSA key", "srv-rsa", "ca-rsa", &["-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256"]),
        ("TLS 1.2 with a P-256 key", "srv-p256", "ca-p256", &["-tls1_2", "-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256"]),
        ("TLS 1.2 AES-256-GCM", "srv-p384", "ca-p384", &["-tls1_2", "-cipher", "ECDHE-ECDSA-AES256-GCM-SHA384"]),
        ("TLS 1.2 ChaCha20-Poly1305", "srv-rsa", "ca-rsa", &["-tls1_2", "-cipher", "ECDHE-RSA-CHACHA20-POLY1305"]),
        ("TLS 1.2 over P-256", "srv-p256", "ca-p256", &["-tls1_2", "-groups", "P-256"]),
        ("TLS 1.2 asking for a certificate", "srv-p256", "ca-p256", &["-tls1_2", "-verify", "1"]),
        ("a good stapled status", "srv-p256", "ca-p256", &["-status_file", "ocsp-good.der"]),
        ("TLS 1.2 with a good stapled status", "srv-p256", "ca-p256", &["-tls1_2", "-status_file", "ocsp-good.der"]),
        ("a must-staple certificate with its status", "staple", "ca-p256", &["-status_file", "ocsp-staple.der"]),
        ("a status from a stranger (ignored)", "srv-p256", "ca-p256", &["-status_file", "ocsp-stranger.der"]),
        ("names its authority may certify", "nc-ok-leaf", "root", &["-cert_chain", "nc-ok.pem"]),
    ];
    for (what, cert, ca, extra) in good {
        let (_server, port) = serve(&dir, dir.join(format!("{cert}.pem")), extra)?;
        let _ = std::fs::remove_file(&out);
        let (ok, err) =
            fetch(&fetch_bin, &dir.join(format!("{ca}.pem")), &format!("https://localhost:{port}/big"), &out)?;
        if !ok || std::fs::read(&out).ok().as_deref() != Some(&body[..]) {
            return Err(format!("TLS interop: {what}: {err}"));
        }
        done.push(*what);
    }
    // Resumption: one fetch of two URLs from the same server, the second
    // connection on the first's ticket (and a server that gives none).
    for (what, extra, want) in [
        ("a resumed session", &[][..], true),
        ("a resumed session after a HelloRetryRequest", &["-groups", "P-256"][..], true),
        ("a server without tickets", &["-num_tickets", "0"][..], false),
    ] {
        let (_server, port) = serve(&dir, dir.join("srv-p256.pem"), extra)?;
        let _ = std::fs::remove_file(&out);
        let url = format!("https://localhost:{port}/big");
        let o = Command::new("/bin/sh")
            .arg("-c")
            .arg("ulimit -v 1048576; exec timeout 30 \"$0\" --ca \"$1\" -o \"$2\" \"$3\" \"$3\"")
            .arg(&fetch_bin)
            .arg(dir.join("ca-p256.pem"))
            .arg(&out)
            .arg(&url)
            .output()
            .map_err(|e| format!("fetch: {e}"))?;
        let err = String::from_utf8_lossy(&o.stderr);
        let mut twice = body.clone();
        twice.extend_from_slice(&body);
        let resumed = err.contains("TLS session resumed");
        if !o.status.success() || std::fs::read(&out).ok().as_deref() != Some(&twice[..]) || resumed != want {
            return Err(format!("TLS interop: {what}: {err}"));
        }
        done.push(what);
    }
    // A KeyUpdate mid-body: the rest still reads; then the server gone
    // without close_notify: refused as maybe cut short.
    let (ok, err, got) = steered(&dir, &fetch_bin)?;
    if got != b"part one\npart two\n" {
        return Err(format!("TLS interop: a KeyUpdate mid-body: {err} (got {:?})", String::from_utf8_lossy(&got)));
    }
    if ok || !err.contains("close_notify") {
        return Err(format!("TLS interop: a body cut short without close_notify was not refused: {err}"));
    }
    done.push("a KeyUpdate mid-body");
    // What must be refused, and why.
    let bad: &[(&str, &str, &str, &[&str], &str)] = &[
        ("the wrong name", "other", "ca-p256", &[], "for another name"),
        ("an expired certificate", "old", "ca-p256", &[], "not valid now"),
        ("an unknown authority", "srv-p256", "ca-rsa", &[], "not from a trusted authority"),
        ("a demand for a client certificate", "srv-p256", "ca-p256", &["-Verify", "1"], "alert"),
        ("a revoked certificate", "srv-p256", "ca-p256", &["-status_file", "ocsp-revoked.der"], "revoked"),
        (
            "TLS 1.2 and a revoked certificate",
            "srv-p256",
            "ca-p256",
            &["-tls1_2", "-status_file", "ocsp-revoked.der"],
            "revoked",
        ),
        ("a must-staple certificate without its status", "staple", "ca-p256", &[], "must come with its OCSP status"),
        (
            "a name outside its authority's permitted names",
            "nc-other-leaf",
            "root",
            &["-cert_chain", "nc-other.pem"],
            "may not certify",
        ),
        (
            "a name its authority excludes",
            "nc-excluded-leaf",
            "root",
            &["-cert_chain", "nc-excluded.pem"],
            "may not certify",
        ),
        (
            "TLS 1.2 with only CBC suites",
            "srv-rsa",
            "ca-rsa",
            &["-tls1_2", "-cipher", "ECDHE-RSA-AES128-SHA256"],
            "alert 40",
        ),
    ];
    for (what, cert, ca, extra, why) in bad {
        let (_server, port) = serve(&dir, dir.join(format!("{cert}.pem")), extra)?;
        let (ok, err) =
            fetch(&fetch_bin, &dir.join(format!("{ca}.pem")), &format!("https://localhost:{port}/big"), &out)?;
        if ok || !err.contains(why) {
            return Err(format!("TLS interop: {what} was not refused as it should be: {err}"));
        }
    }
    println!(
        "xtask: TLS interop passed ({}; refused the wrong name, an expired certificate, an unknown authority, a \
         client-certificate demand, CBC, a revoked certificate, a must-staple one unstapled and names outside \
         constraints; {:.2}s)",
        done.join(", "),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
