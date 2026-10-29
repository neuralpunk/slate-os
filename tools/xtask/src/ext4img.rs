// SPDX-License-Identifier: MIT OR Apache-2.0

//! ext4 images made with the host's e2fsprogs (build-time tools, like
//! QEMU): the test disk the guest's ext4 tests use, and checks of what the
//! guest wrote to it. (The root partition is SlateFS: slatefsimg.rs.)

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Result, run_cmd, target_dir};

pub fn md5(data: &[u8]) -> Result<String> {
    use std::io::Write;
    let mut c = Command::new("md5sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("md5sum: {e}"))?;
    c.stdin.take().unwrap().write_all(data).map_err(|e| e.to_string())?;
    let out = c.wait_with_output().map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&out.stdout).split_whitespace().next().unwrap_or("").to_string())
}

/// Run `mkfs.ext4` on `img` (of `size`), populated from `src`.
pub fn mkfs(img: &Path, size: &str, label: &str, src: &Path) -> Result {
    let _ = std::fs::remove_file(img);
    run_cmd(
        Command::new("mkfs.ext4")
            .args(["-q", "-F", "-b", "4096", "-E", "root_owner=0:0", "-L", label, "-d"])
            .arg(src)
            .arg(img)
            .arg(size),
    )
    .map_err(|e| format!("{e} (is e2fsprogs installed?)"))
}

/// Build `target/ext4-test.img` for tests/shell/ext4.sh.
pub fn test_disk() -> Result<PathBuf> {
    let src = target_dir().join("ext4-test-src");
    let _ = std::fs::remove_dir_all(&src);
    let w = |p: &str, data: &[u8]| -> Result {
        let path = src.join(p);
        std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::write(&path, data).map_err(|e| format!("{}: {e}", path.display()))
    };
    w("hello.txt", b"hello from the host\n")?;
    let mut x = 12345u32;
    let big: Vec<u8> = (0..3_000_000)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (x >> 16) as u8
        })
        .collect();
    w("big.bin", &big)?;
    w("big.md5", format!("{}\n", md5(&big)?).as_bytes())?;
    for i in 1..=500 {
        w(&format!("many/f{i}"), i.to_string().as_bytes())?;
    }
    w("dir/sub/file", b"nested\n")?;
    std::os::unix::fs::symlink("hello.txt", src.join("link")).map_err(|e| e.to_string())?;
    let img = target_dir().join("ext4-test.img");
    mkfs(&img, "64M", "slate-test", &src)?;
    Ok(img)
}

fn debugfs_cat(img: &Path, path: &str) -> Result<Vec<u8>> {
    let out =
        Command::new("debugfs").args(["-R", &format!("cat {path}")]).arg(img).output().map_err(|e| e.to_string())?;
    Ok(out.stdout)
}

/// `e2fsck -fn` on `spec` (a path, optionally `?offset=N`).
fn fsck(spec: &Path, what: &str) -> Result {
    let out = Command::new("e2fsck").args(["-f", "-n"]).arg(spec).output().map_err(|e| e.to_string())?;
    if out.status.success() {
        return Ok(());
    }
    Err(format!(
        "{what}: e2fsck found problems:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ))
}

/// After a power cut: e2fsck recovers a copy of `img` (journal replay and
/// orphans, `-p`), and then finds nothing to fix (`-fn`).
pub fn recover_and_check(img: &Path, what: &str) -> Result {
    let copy = img.with_extension("recovered.img");
    std::fs::copy(img, &copy).map_err(|e| e.to_string())?;
    let out = Command::new("e2fsck").arg("-p").arg(&copy).output().map_err(|e| e.to_string())?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    // Recovery may only replay the journal and free orphans.
    let recovery_line = |l: &str| {
        let msg = l.split_once(": ").map_or(l, |(_, m)| m);
        l.trim().is_empty()
            || msg.starts_with("recovering journal")
            || msg.starts_with("Clearing orphaned inode")
            || msg.ends_with("was not cleanly unmounted, check forced.")
            || msg.contains(" files (")
            || msg.starts_with("clean,")
    };
    if !matches!(out.status.code(), Some(0 | 1)) || !text.lines().all(recovery_line) {
        return Err(format!("{what}: e2fsck had to do more than recover the journal:\n{text}"));
    }
    fsck(&copy, what)
}

/// `e2fsck -fn` on `img`: consistent as it is.
pub fn check(img: &Path, what: &str) -> Result {
    fsck(img, what)
}

/// After the run: the image is consistent (e2fsck finds nothing) and holds
/// what the guest wrote, as e2fsprogs reads it.
pub fn check_test_disk(img: &Path) -> Result {
    fsck(img, "ext4 test disk")?;
    let new = debugfs_cat(img, "/new.txt")?;
    let rand = debugfs_cat(img, "/rand")?;
    let rand_md5 = String::from_utf8_lossy(&debugfs_cat(img, "/rand.md5")?).trim().to_string();
    let deep = debugfs_cat(img, "/moved/d3/f")?;
    if new != b"written by slate\n" || rand.len() != 2_621_440 || md5(&rand)? != rand_md5 || deep != b"deep\n" {
        return Err("ext4 test disk: the guest's files are not on the image as written".into());
    }
    // Written through a shared mapping and left to write-back (the pattern
    // of tests/user/pagecache.c, seed 4).
    let unsynced = debugfs_cat(img, "/unsynced")?;
    let pat = |i: usize| ((i * 31 + 4 * 7 + i / 4093) & 0xff) as u8;
    if unsynced.len() != 8192 || unsynced.iter().enumerate().any(|(i, &b)| b != pat(i)) {
        return Err("ext4 test disk: /unsynced (written through a mapping) is not on the image".into());
    }
    Ok(())
}
