// SPDX-License-Identifier: MIT OR Apache-2.0

//! SlateFS images made with Slate's own `slatefs` tool, which also runs on
//! the host (ADR 0026): the root partition with its `system-1`, `home` and
//! `var` subvolumes (ADR 0027), and checks of what the guest wrote.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Result, run_cmd};

/// The slatefs binary (built with the rest of the userland).
fn tool() -> Result<PathBuf> {
    crate::userland::build()?
        .into_iter()
        .find(|p| p.name == "slatefs")
        .map(|p| p.path)
        .ok_or_else(|| "slatefs was not built".into())
}

fn ok(out: std::process::Output, what: &str) -> Result<std::process::Output> {
    if out.status.success() {
        return Ok(out);
    }
    Err(format!("slatefs {what}: {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

/// The root partition at `offset` (of `size` bytes): `system-1` from
/// `stage`, `var` and `home` from its /var and /home, `system-1` set to boot.
pub fn make_root(img: &Path, offset: u64, size: u64, stage: &Path) -> Result {
    let t = tool()?;
    let base = |c: &mut Command| {
        c.arg("--offset").arg(offset.to_string());
    };
    let mut mkfs = Command::new(&t);
    base(&mut mkfs);
    mkfs.args(["mkfs", "-L", "slate-root", "-s", "system-1", "--size"])
        .arg(size.to_string())
        .arg("-d")
        .arg(stage)
        .args(["--owner", "0:0"])
        .arg(img)
        .stdout(std::process::Stdio::null());
    run_cmd(&mut mkfs)?;
    for sub in ["var", "home"] {
        let mut c = Command::new(&t);
        base(&mut c);
        c.arg("populate").arg(img).arg(sub).arg(stage.join(sub)).args(["--owner", "0:0"]);
        run_cmd(&mut c)?;
    }
    let mut boot = Command::new(&t);
    base(&mut boot);
    boot.arg("boot").arg(img).arg("default=system-1").stdout(std::process::Stdio::null());
    run_cmd(&mut boot)?;
    fsck(img, offset, "SlateFS root")
}

/// `slatefs fsck` must find nothing.
pub fn fsck(img: &Path, offset: u64, what: &str) -> Result {
    fsck_with(img, offset, what, None)
}

/// fsck, opening an encrypted partition with `password` (ADR 0036).
pub fn fsck_with(img: &Path, offset: u64, what: &str, password: Option<&str>) -> Result {
    let mut c = Command::new(tool()?);
    c.arg("--offset").arg(offset.to_string());
    if let Some(p) = password {
        let file = crate::target_dir().join("slatefs-password");
        std::fs::write(&file, p).map_err(|e| e.to_string())?;
        c.arg("--password-file").arg(file);
    }
    let out = c.arg("fsck").arg(img).output().map_err(|e| format!("slatefs: {e}"))?;
    ok(out, &format!("fsck of the {what}")).map(|_| ())
}

/// A file's contents in subvolume `SUBVOL:` or the boot default.
pub fn cat(img: &Path, offset: u64, spec: &str) -> Result<Vec<u8>> {
    let out = Command::new(tool()?)
        .arg("--offset")
        .arg(offset.to_string())
        .arg("cat")
        .arg(img)
        .arg(spec)
        .output()
        .map_err(|e| format!("slatefs: {e}"))?;
    Ok(ok(out, &format!("cat {spec}"))?.stdout)
}

/// After a session: consistent, and holding what it wrote.
pub fn check_root(img: &Path, offset: u64, spec: &str, want: &[u8]) -> Result {
    fsck(img, offset, "SlateFS root after the session")?;
    let got = cat(img, offset, spec)?;
    if got != want {
        return Err(format!(
            "SlateFS root: {spec} holds {:?}, want {:?}",
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(want)
        ));
    }
    Ok(())
}

/// `target/slatefs-test.img` for tests/shell/slatefs.sh (/dev/vdd).
pub fn test_disk() -> Result<std::path::PathBuf> {
    let src = crate::target_dir().join("slatefs-test-src");
    let _ = std::fs::remove_dir_all(&src);
    std::fs::create_dir_all(&src).map_err(|e| e.to_string())?;
    std::fs::write(src.join("hello.txt"), "hello from the host\n").map_err(|e| e.to_string())?;
    let img = crate::target_dir().join("slatefs-test.img");
    let _ = std::fs::remove_file(&img);
    let mut c = Command::new(tool()?);
    c.args(["mkfs", "-L", "slate-test", "-s", "root", "--size", "64M", "-d"])
        .arg(&src)
        .args(["--owner", "0:0"])
        .arg(&img)
        .stdout(std::process::Stdio::null());
    run_cmd(&mut c)?;
    Ok(img)
}

/// After the run: consistent, and holding what the guest left.
pub fn check_test_disk(img: &Path) -> Result {
    fsck(img, 0, "SlateFS test disk")?;
    let want: [(&str, &[u8]); 4] =
        [("/hello.txt", b"changed\n"), ("/new.txt", b"wri"), ("/hard", b"wri"), ("/moved/b/c/f", b"deep\n")];
    for (path, data) in want {
        let got = cat(img, 0, path)?;
        if got != data {
            return Err(format!("SlateFS test disk: {path} holds {:?}", String::from_utf8_lossy(&got)));
        }
    }
    if cat(img, 0, "/rand").is_ok() {
        return Err("SlateFS test disk: /rand should be gone".into());
    }
    Ok(())
}
