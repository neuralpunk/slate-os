// SPDX-License-Identifier: MIT OR Apache-2.0

//! A distribution a box can hold (ADR 0183): `/usr/share/slate/boxes/
//! NAME.distro`, lines of `key value` (`#` starts a comment):
//!
//! - `title`: what people see ("Arch Linux");
//! - `release`: the pinned release;
//! - `url`: the root's tarball (zstd or gzip), `{release}` and `{mirror}`
//!   filled in; `signature` its detached OpenPGP signature (`{url}.sig`
//!   unless given);
//! - `fingerprint`, `key`: the maker's signing key, its fingerprint (40
//!   hex digits) and its public key packet (hex); the packet must have
//!   that fingerprint;
//! - `strip`: leading folders of the tarball's names to drop;
//! - `mirror`: where packages come from;
//! - `shell`: the box's login shell;
//! - `setup`: a command the base runs as its root, once, in order (any
//!   number; `{mirror}` filled in);
//! - `clean`: the command that empties the distribution's package cache
//!   (`slate-box clean`, Settings).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Where distributions are described.
pub const DIR: &str = "/usr/share/slate/boxes";
/// The distribution boxes get unless another is named.
pub const DEFAULT: &str = "arch";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Distro {
    pub name: String,
    pub title: String,
    pub release: String,
    pub url: String,
    pub signature: String,
    pub fingerprint: String,
    pub key: Vec<u8>,
    pub strip: usize,
    pub mirror: String,
    pub shell: String,
    pub setup: Vec<String>,
    pub clean: Option<String>,
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

impl Distro {
    pub fn parse(name: &str, text: &str) -> Result<Distro, String> {
        let mut d = Distro {
            name: String::from(name),
            title: String::from(name),
            release: String::new(),
            url: String::new(),
            signature: String::from("{url}.sig"),
            fingerprint: String::new(),
            key: Vec::new(),
            strip: 0,
            mirror: String::new(),
            shell: String::from("/bin/sh"),
            setup: Vec::new(),
            clean: None,
        };
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (k, v) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            let v = String::from(v.trim());
            match k {
                "title" => d.title = v,
                "release" => d.release = v,
                "url" => d.url = v,
                "signature" => d.signature = v,
                "fingerprint" => d.fingerprint = v.replace(' ', "").to_ascii_uppercase(),
                "key" => d.key = unhex(&v).ok_or_else(|| format!("{name}.distro:{}: the key isn't hex", n + 1))?,
                "strip" => d.strip = v.parse().map_err(|_| format!("{name}.distro:{}: strip isn't a number", n + 1))?,
                "mirror" => d.mirror = String::from(v.trim_end_matches('/')),
                "shell" => d.shell = v,
                "setup" => d.setup.push(v),
                "clean" => d.clean = Some(v),
                _ => return Err(format!("{name}.distro:{}: unknown key {k}", n + 1)),
            }
        }
        if d.url.is_empty() || d.key.is_empty() || d.fingerprint.len() != 40 {
            return Err(format!("{name}.distro: it needs url, key and a fingerprint of 40 hex digits"));
        }
        Ok(d)
    }

    fn fill(&self, s: &str, url: &str) -> String {
        s.replace("{release}", &self.release).replace("{mirror}", &self.mirror).replace("{url}", url)
    }

    /// The tarball's URL and its signature's: `from` instead of the
    /// distribution's own when given (a local copy, a test's server).
    pub fn urls(&self, from: Option<&str>) -> (String, String) {
        let url = match from {
            Some(f) => String::from(f),
            None => self.fill(&self.url, ""),
        };
        let sig = self.fill(&self.signature, &url);
        (url, sig)
    }

    /// The setup commands, filled in.
    pub fn setup_commands(&self) -> Vec<String> {
        self.setup.iter().map(|s| self.fill(s, "")).collect()
    }

    /// The signing key, checked against the pinned fingerprint.
    pub fn signing_key(&self) -> Result<slate_pgp::Key, String> {
        let k = slate_pgp::Key::parse(&self.key).map_err(|e| format!("{}'s signing key: {e}", self.title))?;
        if k.fingerprint_hex() != self.fingerprint {
            return Err(format!(
                "{}'s signing key has the fingerprint {}, not the pinned {}",
                self.title,
                k.fingerprint_hex(),
                self.fingerprint
            ));
        }
        Ok(k)
    }
}

/// The distribution `name`, from [`DIR`].
pub fn load(name: &str) -> Result<Distro, String> {
    if !name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') || name.is_empty() {
        return Err(format!("{name} isn't a distribution's name"));
    }
    let path = format!("{DIR}/{name}.distro");
    let text = slate_rt::fs::read_file(path.as_bytes())
        .map_err(|_| format!("there is no distribution {name} (slate-box distros lists them)"))?;
    Distro::parse(name, &slate_rt::lossy(&text))
}

/// The distributions there are: their names.
pub fn all() -> Vec<String> {
    let mut out: Vec<String> = slate_rt::fs::read_dir(DIR.as_bytes())
        .unwrap_or_default()
        .iter()
        .filter_map(|e| Some(String::from(slate_rt::lossy(&e.name).strip_suffix(".distro")?)))
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARCH: &str = include_str!("../../../rootfs/usr/share/slate/boxes/arch.distro");

    #[test]
    fn arch() {
        let d = Distro::parse("arch", ARCH).unwrap();
        assert_eq!(d.title, "Arch Linux");
        assert_eq!(d.strip, 1);
        let (url, sig) = d.urls(None);
        assert_eq!(
            url,
            alloc::format!("https://geo.mirror.pkgbuild.com/iso/{0}/archlinux-bootstrap-{0}-x86_64.tar.zst", d.release)
        );
        assert_eq!(sig, alloc::format!("{url}.sig"));
        assert_eq!(d.signing_key().unwrap().fingerprint_hex(), "3E80CA1A8B89F69CBA57D98A76A5EF9054449A5C");
        assert!(d.setup_commands().iter().any(|c| c.contains("https://geo.mirror.pkgbuild.com/$repo/os/$arch")));
        assert_eq!(d.urls(Some("http://10.0.2.2:80/x.tar.zst")).1, "http://10.0.2.2:80/x.tar.zst.sig");
    }

    #[test]
    fn refused() {
        assert!(Distro::parse("x", "title X\n").is_err());
        assert!(Distro::parse("x", "bogus 1\n").is_err());
        let mut d = Distro::parse("arch", ARCH).unwrap();
        d.fingerprint = String::from("0000000000000000000000000000000000000000");
        assert!(d.signing_key().unwrap_err().contains("not the pinned"));
    }
}
