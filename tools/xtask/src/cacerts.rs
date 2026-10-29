// SPDX-License-Identifier: MIT OR Apache-2.0

//! `cargo xtask cacerts`: Mozilla's certificate authorities as curl
//! publishes them (https://curl.se/docs/caextract.html), into
//! `rootfs/etc/ssl/certs/ca-certificates.crt`, the `ca-certificates`
//! package's file (ADR 0072's addendum). The bundle is fetched with the
//! host's curl, checked against curl's published SHA-256 and the date in
//! its header, and written only if it is newer. `SLATE_CACERT=FILE` takes
//! the bundle from FILE instead (its own `FILE.sha256` beside it).

use std::process::Command;

use crate::{Result, root};

const URL: &str = "https://curl.se/ca/cacert.pem";

fn fetch(url: &str) -> Result<Vec<u8>> {
    let out = Command::new("curl")
        .args(["--fail", "--silent", "--show-error", "--location", "--max-time", "60", url])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() {
        return Err(format!("{url}: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(out.stdout)
}

/// The hash in a `sha256sum`-style line ("HEX  cacert.pem").
pub fn published_hash(text: &str) -> Option<String> {
    let h = text.split_whitespace().next()?;
    (h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())).then(|| h.to_ascii_lowercase())
}

pub fn update() -> Result {
    let (bundle, sum) = match std::env::var("SLATE_CACERT") {
        Ok(f) => (
            std::fs::read(&f).map_err(|e| format!("{f}: {e}"))?,
            std::fs::read(format!("{f}.sha256")).map_err(|e| format!("{f}.sha256: {e}"))?,
        ),
        Err(_) => (fetch(URL)?, fetch(&format!("{URL}.sha256"))?),
    };
    let want = published_hash(&String::from_utf8_lossy(&sum)).ok_or("the published SHA-256 doesn't parse")?;
    let got = slate_hash::hex(&slate_hash::sha256(&bundle));
    if got != want {
        return Err(format!("the bundle's SHA-256 is {got}, curl publishes {want}"));
    }
    let text = String::from_utf8_lossy(&bundle);
    let new = crate::basepkg::ca_version(&text).ok_or("the bundle has no \"Certificate data from Mozilla\" date")?;
    let path = root().join("rootfs/etc/ssl/certs/ca-certificates.crt");
    let old = std::fs::read_to_string(&path).ok().and_then(|t| crate::basepkg::ca_version(&t));
    if old.as_deref().is_some_and(|o| o >= new.as_str()) {
        println!("xtask: cacerts: the bundle of {} is the newest (curl's is {new})", old.unwrap_or_default());
        return Ok(());
    }
    let roots = text.matches("-----BEGIN CERTIFICATE-----").count();
    std::fs::write(&path, &bundle).map_err(|e| format!("{}: {e}", path.display()))?;
    println!(
        "xtask: cacerts: ca-certificates {new} ({roots} roots, SHA-256 {got}); \
         record it in docs/DEPENDENCIES.md (\"Data files\")"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes() {
        let h = "796f1389bfea13c0ed78f663b765baaff54a508e5483786bd6ece73c5e3e3cbe";
        assert_eq!(published_hash(&format!("{h}  cacert.pem\n")).as_deref(), Some(h));
        assert_eq!(published_hash("not a hash  cacert.pem"), None);
    }
}
