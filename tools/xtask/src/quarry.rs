// SPDX-License-Identifier: MIT OR Apache-2.0

//! quarry's keys and test repositories (ADR 0025). xtask runs Slate's own
//! quarry binary on the host (our programs also run there) to make the
//! checkout's development key and to pack and index the test packages in
//! tests/quarry.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Result, root, run_cmd, target_dir};

fn dir() -> PathBuf {
    target_dir().join("quarry")
}

/// The quarry binary (built with the rest of the userland).
fn quarry() -> Result<PathBuf> {
    let built = crate::userland::build()?;
    built.into_iter().find(|p| p.name == "quarry").map(|p| p.path).ok_or_else(|| "quarry was not built".into())
}

fn run_quarry(args: &[&std::ffi::OsStr]) -> Result {
    run_cmd(Command::new(quarry()?).args(args).stdout(std::process::Stdio::null()))
}

/// A key pair under target/quarry, made once: (secret, public), in the
/// form `quarry keygen` writes. Made here rather than by quarry, which the
/// key signs when it is built (ADR 0090).
fn key(name: &str) -> Result<(PathBuf, PathBuf)> {
    use std::io::Read;
    let d = dir();
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    let (secret, public) = (d.join(format!("{name}.key")), d.join(format!("{name}.pub")));
    if !secret.exists() || !public.exists() {
        let mut seed = [0u8; 32];
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut seed)).map_err(|e| e.to_string())?;
        let k = slate_qpkg::SecretKey::from_seed(seed);
        std::fs::write(&secret, k.to_text()).map_err(|e| format!("{}: {e}", secret.display()))?;
        std::fs::set_permissions(&secret, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .map_err(|e| e.to_string())?;
        std::fs::write(&public, k.public().to_text()).map_err(|e| format!("{}: {e}", public.display()))?;
    }
    Ok((secret, public))
}

/// Where the development public key is (made if it is not there yet).
pub fn dev_public_key_path() -> Result<PathBuf> {
    Ok(key("dev")?.1)
}

/// The checkout's development public key, which every image built here
/// trusts. It is never committed; release keys are the owner's decision.
pub fn dev_public_key() -> Result<Vec<u8>> {
    let (_, public) = key("dev")?;
    std::fs::read(public).map_err(|e| e.to_string())
}

/// HTTPS for the test repositories (ADR 0053): a certificate authority
/// the test images trust, and a certificate for `slate-repo` and 10.0.2.2,
/// made with the host's OpenSSL in target/quarry/tls. None without it.
pub fn test_tls() -> Result<Option<PathBuf>> {
    if Command::new("openssl").arg("version").output().is_err() {
        return Ok(None);
    }
    let d = dir().join("tls");
    if d.join("repo.pem").exists() && d.join("ca.pem").exists() {
        return Ok(Some(d));
    }
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    crate::tlstest::authority(&d, "ca", "p256")?;
    let ext = "subjectAltName=DNS:slate-repo,IP:10.0.2.2\nextendedKeyUsage=serverAuth\n";
    crate::tlstest::issue(&d, "repo", "p256", "ca", ext, &[])?;
    Ok(Some(d))
}

/// The development key itself (it signs the base system's packages).
pub fn dev_secret() -> Result<slate_qpkg::SecretKey> {
    let (secret, _) = key("dev")?;
    let text = std::fs::read_to_string(&secret).map_err(|e| format!("{}: {e}", secret.display()))?;
    slate_qpkg::SecretKey::parse(&text).map_err(|e| format!("{}: {e:?}", secret.display()))
}

/// A detached signature (as quarry's INDEX.sig) of `data` with the
/// development key: the install media's system payload (ADR 0029).
pub fn sign_detached(data: &[u8]) -> Result<Vec<u8>> {
    Ok(slate_qpkg::archive::sign_trailer(data, &dev_secret()?))
}

/// Pack tests/quarry/<src> with `key` into `out`.
fn pack(src: &str, key: &Path, out: &Path) -> Result {
    let base = root().join("tests/quarry").join(src);
    let tree = if src.starts_with("qhello") {
        qhello_tree()?
    } else if src.starts_with("qapp") || src.starts_with("qbare") {
        qapp_tree(src.split('-').next().unwrap())?
    } else {
        base.join("root")
    };
    run_quarry(&["pack".as_ref(), tree.as_os_str(), base.join("QUARRY").as_os_str(), key.as_os_str(), out.as_os_str()])
}

/// qhello's tree: the C program built static with musl-gcc (a test load).
fn qhello_tree() -> Result<PathBuf> {
    let tree = dir().join("qhello-tree");
    let bin = tree.join("usr/bin");
    std::fs::create_dir_all(&bin).map_err(|e| e.to_string())?;
    let cc = std::env::var("SLATE_MUSL_CC").unwrap_or_else(|_| "musl-gcc".into());
    run_cmd(
        Command::new(cc)
            .args(["-O2", "-static", "-o"])
            .arg(bin.join("qhello"))
            .arg(root().join("tests/quarry/qhello-1.0/qhello.c")),
    )?;
    Ok(tree)
}

/// The test app's tree as package `name` (ADR 0130): tests/quarry/qapp-1.0
/// built native with tools/slate-cc, as /usr/bin/NAME, unsigned.
fn qapp_tree(name: &str) -> Result<PathBuf> {
    let tree = dir().join(format!("{name}-tree"));
    let bin = tree.join("usr/bin");
    std::fs::create_dir_all(&bin).map_err(|e| e.to_string())?;
    let sysroot = crate::userland::sysroot()?;
    run_cmd(
        Command::new(root().join("tools/slate-cc"))
            .env("SLATE_SYSROOT", &sysroot)
            .args(["-O2", "-Wall", "-Wextra", "-Werror", "-o"])
            .arg(bin.join(name))
            .arg(root().join("tests/quarry/qapp-1.0/qapp.c")),
    )?;
    Ok(tree)
}

/// Build the test repositories under target/quarry/www and the rejected
/// packages for /test/quarry; returns the web root. Once per run: the
/// servers serve this directory while images are built.
pub fn test_repos() -> Result<PathBuf> {
    static DONE: std::sync::OnceLock<std::result::Result<PathBuf, String>> = std::sync::OnceLock::new();
    DONE.get_or_init(make_test_repos).clone()
}

fn make_test_repos() -> Result<PathBuf> {
    let (dev, _) = key("dev")?;
    let (other, _) = key("untrusted")?;
    let www = dir().join("www");
    let _ = std::fs::remove_dir_all(&www);
    let repo = |name: &str, pkgs: &[&str], signer: &Path| -> Result<PathBuf> {
        let r = www.join(name);
        std::fs::create_dir_all(r.join("pkgs")).map_err(|e| e.to_string())?;
        for p in pkgs {
            pack(p, signer, &r.join("pkgs").join(format!("{p}.qpk")))?;
        }
        run_quarry(&["index".as_ref(), r.as_os_str(), signer.as_os_str()])?;
        Ok(r)
    };
    repo("v1", &["hello-1.0", "libgreet-1", "qhello-1.0"], &dev)?;
    repo("v2", &["hello-1.0", "hello-1.1", "libgreet-1", "qhello-1.0"], &dev)?;
    // Apps with permissions, and one declaring a permission Slate lacks.
    repo("apps", &["qapp-1.0", "qbare-1.0", "qbad-1.0"], &dev)?;
    // A package changed after indexing: its SHA-256 no longer matches.
    let bad = repo("bad", &["libgreet-1"], &dev)?;
    let pkg = bad.join("pkgs/libgreet-1.qpk");
    let mut data = std::fs::read(&pkg).map_err(|e| e.to_string())?;
    let at = data.len() / 2;
    data[at] ^= 0xff;
    std::fs::write(&pkg, data).map_err(|e| e.to_string())?;
    repo("forged", &["libgreet-1"], &other)?;
    // Packages the guest must refuse to install from a file.
    let rejects = dir().join("rejects");
    std::fs::create_dir_all(&rejects).map_err(|e| e.to_string())?;
    let signed = rejects.join("signed.qpk");
    pack("libgreet-1", &dev, &signed)?;
    let data = std::fs::read(&signed).map_err(|e| e.to_string())?;
    // The signature record is the last 81 bytes: kind, length, key id, signature.
    std::fs::write(rejects.join("unsigned.qpk"), &data[..data.len() - 81]).map_err(|e| e.to_string())?;
    pack("libgreet-1", &other, &rejects.join("untrusted.qpk"))?;
    std::fs::remove_file(&signed).map_err(|e| e.to_string())?;
    Ok(www)
}

/// The rejected packages for /test/quarry (after [`test_repos`]).
pub fn rejects() -> Result<Vec<(String, Vec<u8>)>> {
    let d = dir().join("rejects");
    let mut out = Vec::new();
    for name in ["unsigned.qpk", "untrusted.qpk"] {
        out.push((name.to_string(), std::fs::read(d.join(name)).map_err(|e| format!("{name}: {e}"))?));
    }
    Ok(out)
}
