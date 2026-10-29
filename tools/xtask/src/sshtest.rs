// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-sshd against the host's OpenSSH client, on the host (ADR 0030,
//! ADR 0061): our sshd runs as the developer, so only that account logs
//! in, with a key. Part of `cargo xtask check`; skipped when the host has
//! no OpenSSH client.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::{Result, run_cmd, target_dir};

fn free_port() -> Result<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    Ok(l.local_addr().map_err(|e| e.to_string())?.port())
}

struct Server {
    child: Child,
    log: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start our sshd with `config`; wait for its "listening" line.
fn start(sshd: &Path, config: &Path, dir: &Path) -> Result<Server> {
    let log = dir.join("sshd.log");
    let err = std::fs::File::create(&log).map_err(|e| e.to_string())?;
    // Capped like every program of ours run on the host.
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg("ulimit -v 1048576; exec timeout 600 \"$0\" -f \"$1\"")
        .arg(sshd)
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(err)
        .spawn()
        .map_err(|e| format!("sshd: {e}"))?;
    let s = Server { child, log };
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if std::fs::read_to_string(&s.log).is_ok_and(|t| t.contains("listening on port")) {
            return Ok(s);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!("sshd did not start: {}", std::fs::read_to_string(&s.log).unwrap_or_default()))
}

pub fn interop() -> Result {
    if Command::new("ssh").arg("-V").output().is_err() {
        println!("xtask: sshd interop skipped (no OpenSSH client on the host)");
        return Ok(());
    }
    let started = Instant::now();
    let sshd = crate::userland::symbols_dir().join("sshd");
    let dir = target_dir().join("sshd-interop");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let key = dir.join("id");
    run_cmd(Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", ""]).arg("-f").arg(&key))?;
    std::fs::copy(key.with_extension("pub"), dir.join("authorized_keys")).map_err(|e| e.to_string())?;
    let port = free_port()?;
    let config = dir.join("sshd_config");
    let d = dir.display();
    std::fs::write(
        &config,
        format!(
            "Port {port}\nHostKey {d}/host_key\nAuthorizedKeysFile {d}/authorized_keys\nPasswordAuthentication no\n\
             RekeyLimit 256K\nClientAliveInterval 1\nClientAliveCountMax 3\nUsePAM no\n"
        ),
    )
    .map_err(|e| e.to_string())?;
    // A configuration error stops sshd before it listens.
    let bad = dir.join("bad_config");
    std::fs::write(&bad, "Port 22\nMatch User nobody\n").map_err(|e| e.to_string())?;
    let out = Command::new("timeout").arg("10").arg(&sshd).arg("-t").arg("-f").arg(&bad).output();
    let out = out.map_err(|e| e.to_string())?;
    if out.status.success() || !String::from_utf8_lossy(&out.stderr).contains("line 2: match is not supported") {
        return Err(format!("sshd -t accepted a Match block: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let server = start(&sshd, &config, &dir)?;
    let user = std::env::var("USER").unwrap_or_else(|_| "root".into());
    let ssh = |extra: &[&str], cmd: &str, stdin: Option<&Path>| -> Result<(i32, String, String)> {
        let mut c = Command::new("timeout");
        c.args(["60", "ssh", "-F", "/dev/null", "-p", &port.to_string()]);
        c.args(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes"]);
        c.args(["-o", "IdentitiesOnly=yes", "-i"]).arg(&key);
        c.args(extra).arg(format!("{user}@127.0.0.1")).arg(cmd);
        c.stdin(match stdin {
            Some(p) => Stdio::from(std::fs::File::open(p).map_err(|e| e.to_string())?),
            None => Stdio::null(),
        });
        let out = c.output().map_err(|e| format!("ssh: {e}"))?;
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        Ok((out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr)))
    };
    let fail = |what: &str, r: &(i32, String, String)| -> Result {
        let log = std::fs::read_to_string(&server.log).unwrap_or_default();
        Err(format!("sshd interop: {what}: status {}, out {:?}, err {:?}; sshd log:\n{log}", r.0, r.1, r.2))
    };
    // The post-quantum hybrid, and X25519 alone.
    for kex in ["mlkem768x25519-sha256", "curve25519-sha256"] {
        let r = ssh(&["-v", "-o", &format!("KexAlgorithms={kex}")], "echo kex-$((40+2))", None)?;
        if r.0 != 0 || !r.1.contains("kex-42") || !r.2.contains(&format!("kex: algorithm: {kex}")) {
            return fail(kex, &r);
        }
    }
    // The client's default choice is the hybrid.
    let r = ssh(&["-v"], "true", None)?;
    if r.0 != 0 || !r.2.contains("kex: algorithm: mlkem768x25519-sha256") {
        return fail("default key exchange", &r);
    }
    let r = ssh(&[], "exit 3", None)?;
    if r.0 != 3 {
        return fail("exit status", &r);
    }
    // Past RekeyLimit (256K) the server starts key exchanges itself, in
    // both directions of traffic.
    let r = ssh(&[], "head -c 3000000 /dev/zero | wc -c", None)?;
    if r.0 != 0 || r.1.trim() != "3000000" {
        return fail("data within the session", &r);
    }
    let r = ssh(&["-v"], "head -c 3000000 /dev/zero", None)?;
    let kexes = r.2.matches("SSH2_MSG_KEXINIT received").count();
    if r.0 != 0 || r.1.len() != 3_000_000 || kexes < 5 {
        return fail("3 MB to the client, rekeyed", &(r.0, format!("{} bytes, {kexes} key exchanges", r.1.len()), r.2));
    }
    let upload = dir.join("upload");
    std::fs::write(&upload, vec![b'x'; 2_000_000]).map_err(|e| e.to_string())?;
    let r = ssh(&[], "wc -c", Some(&upload))?;
    if r.0 != 0 || r.1.trim() != "2000000" {
        return fail("2 MB from the client", &r);
    }
    // ClientAliveInterval 1: an idle but live client is asked and answers.
    let r = ssh(&[], "sleep 4; echo still-$((1+1))", None)?;
    if r.0 != 0 || !r.1.contains("still-2") {
        return fail("keepalives", &r);
    }
    // SFTP (ADR 0061): OpenSSH's sftp, and scp, which speaks SFTP.
    let files = dir.join("files");
    std::fs::create_dir_all(&files).map_err(|e| e.to_string())?;
    let payload = dir.join("payload");
    let data: Vec<u8> = (0..1_500_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    std::fs::write(&payload, &data).map_err(|e| e.to_string())?;
    let common = |c: &mut Command| {
        c.args(["-F", "/dev/null", "-P", &port.to_string()]);
        c.args(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes"]);
        c.args(["-o", "IdentitiesOnly=yes", "-i"]).arg(&key);
    };
    let (f, dd) = (files.display(), dir.display());
    let batch = dir.join("batch");
    std::fs::write(
        &batch,
        format!(
            "cd {f}\nput {dd}/payload up.bin\nls -l up.bin\nrename up.bin moved.bin\nmkdir sub\n\
             put {dd}/payload sub/second.bin\nget moved.bin {dd}/back.bin\ndf .\nrm sub/second.bin\nrmdir sub\n\
             symlink moved.bin link.bin\nchmod 600 moved.bin\nls\n"
        ),
    )
    .map_err(|e| e.to_string())?;
    let mut c = Command::new("timeout");
    c.args(["60", "sftp"]);
    common(&mut c);
    c.arg("-b").arg(&batch).arg(format!("{user}@127.0.0.1")).stdin(Stdio::null());
    let out = c.output().map_err(|e| format!("sftp: {e}"))?;
    let r = (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(files.join("moved.bin")).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
    if r.0 != 0
        || std::fs::read(dir.join("back.bin")).ok().as_deref() != Some(data.as_slice())
        || std::fs::read_link(files.join("link.bin")).ok() != Some(PathBuf::from("moved.bin"))
        || files.join("sub").exists()
        || mode != 0o600
        || !r.1.contains("-rw")
    {
        return fail("sftp", &r);
    }
    // scp both ways, and a directory tree with -r.
    std::fs::create_dir_all(dir.join("tree/a")).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("tree/a/b.txt"), "in a tree\n").map_err(|e| e.to_string())?;
    let remote = |p: &str| format!("{user}@127.0.0.1:{f}/{p}");
    for (args, what) in [
        (vec![payload.display().to_string(), remote("scp.bin")], "scp up"),
        (vec![remote("scp.bin"), format!("{dd}/scp-back.bin")], "scp down"),
        (vec!["-r".into(), format!("{dd}/tree"), remote("")], "scp -r"),
    ] {
        let mut c = Command::new("timeout");
        c.args(["60", "scp", "-q"]);
        common(&mut c);
        c.args(&args).stdin(Stdio::null());
        let out = c.output().map_err(|e| format!("scp: {e}"))?;
        if !out.status.success() {
            let r = (
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stdout).into_owned(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            );
            return fail(what, &r);
        }
    }
    if std::fs::read(dir.join("scp-back.bin")).ok().as_deref() != Some(data.as_slice())
        || std::fs::read_to_string(files.join("tree/a/b.txt")).ok().as_deref() != Some("in a tree\n")
    {
        return fail("scp contents", &(0, String::new(), String::new()));
    }
    drop(server);
    println!(
        "xtask: sshd interop passed (ML-KEM hybrid, X25519, rekeys, keepalives, sftp, scp; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
