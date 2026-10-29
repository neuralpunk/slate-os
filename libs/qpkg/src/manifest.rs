// SPDX-License-Identifier: MIT OR Apache-2.0

//! Package manifests and index entries: `key: value` paragraphs (ADR 0025).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::Error;
use crate::version::Op;

/// The permissions an app may declare (ADR 0130), which the kernel enforces
/// for its programs: internet sockets, the users' files, Strata's socket,
/// GPUs, input devices, sound cards, generating code. `none` declares none.
pub const PERMISSIONS: &[&str] = &["network", "home", "display", "gpu", "input", "audio", "jit"];

/// What a package was built for (ADR 0022).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Abi {
    /// Slate's own programs and software built for Slate.
    Slate,
    /// Linux binaries (Linux compatibility mode).
    Linux,
    /// Scripts and data.
    Any,
}

impl Abi {
    pub fn parse(s: &str) -> Option<Abi> {
        match s {
            "slate" => Some(Abi::Slate),
            "linux" => Some(Abi::Linux),
            "any" => Some(Abi::Any),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Abi::Slate => "slate",
            Abi::Linux => "linux",
            Abi::Any => "any",
        }
    }
}

/// A dependency: a package name and a version requirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dep {
    pub name: String,
    pub op: Op,
    pub version: String,
}

impl Dep {
    /// `name` or `name (>= 1.0)`.
    pub fn parse(s: &str) -> Result<Dep, Error> {
        let s = s.trim();
        let Some((name, rest)) = s.split_once('(') else {
            return valid_name(s).map(|n| Dep { name: n.into(), op: Op::Any, version: String::new() });
        };
        let rest = rest.trim().strip_suffix(')').ok_or(Error::Format("dependency: missing ')'"))?.trim();
        let (op, version) = [(">=", Op::Ge), ("<=", Op::Le), (">>", Op::Gt), ("<<", Op::Lt), ("=", Op::Eq)]
            .iter()
            .find_map(|(sym, op)| rest.strip_prefix(sym).map(|v| (*op, v.trim())))
            .ok_or(Error::Format("dependency: unknown operator"))?;
        if version.is_empty() {
            return Err(Error::Format("dependency: missing version"));
        }
        Ok(Dep { name: valid_name(name.trim())?.into(), op, version: version.into() })
    }

    pub fn allows(&self, version: &str) -> bool {
        self.op.allows(version, &self.version)
    }
}

impl core::fmt::Display for Dep {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.op {
            Op::Any => write!(f, "{}", self.name),
            op => write!(f, "{} ({} {})", self.name, op.symbol(), self.version),
        }
    }
}

/// Package names: lowercase letters, digits and `+-._`, starting with a
/// letter or digit.
fn valid_name(s: &str) -> Result<&str, Error> {
    let ok = !s.is_empty()
        && s.len() <= 64
        && s.bytes().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"+-._".contains(&c));
    if ok { Ok(s) } else { Err(Error::Format("bad package name")) }
}

/// A package's metadata. In an index, `file`, `size` and `sha256` say
/// where the package is and what it must hash to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub abi: Abi,
    pub summary: String,
    pub license: String,
    pub depends: Vec<Dep>,
    pub permissions: Vec<String>,
    /// Configuration files (paths in the package): an upgrade keeps the
    /// administrator's changes to them (ADR 0069).
    pub config: Vec<String>,
    /// Part of the system itself: never removed (ADR 0071).
    pub essential: bool,
    pub installed_size: u64,
    pub file: String,
    pub size: u64,
    pub sha256: String,
}

impl Manifest {
    pub fn new(name: &str, version: &str) -> Manifest {
        Manifest {
            name: name.into(),
            version: version.into(),
            arch: "noarch".into(),
            abi: Abi::Any,
            summary: String::new(),
            license: String::new(),
            depends: Vec::new(),
            permissions: Vec::new(),
            config: Vec::new(),
            essential: false,
            installed_size: 0,
            file: String::new(),
            size: 0,
            sha256: String::new(),
        }
    }

    /// Permissions the manifest names that Slate doesn't know (ADR 0130):
    /// quarry refuses such a package.
    pub fn unknown_permissions(&self) -> Vec<&str> {
        self.permissions.iter().map(String::as_str).filter(|p| *p != "none" && !PERMISSIONS.contains(p)).collect()
    }

    /// `name-version`, as people refer to a package.
    pub fn id(&self) -> String {
        format!("{}-{}", self.name, self.version)
    }

    /// The file name a package is stored under.
    pub fn file_name(&self) -> String {
        format!("{}-{}.{}.qpk", self.name, self.version, self.arch)
    }

    /// Parse one paragraph.
    pub fn parse(text: &str) -> Result<Manifest, Error> {
        let mut m = Manifest::new("", "");
        let (mut have_name, mut have_version, mut have_abi) = (false, false, false);
        for (key, value) in fields(text)? {
            match key {
                "name" => {
                    m.name = valid_name(&value)?.into();
                    have_name = true;
                }
                "version" => {
                    if value.is_empty() || value.contains(char::is_whitespace) {
                        return Err(Error::Format("bad version"));
                    }
                    m.version = value;
                    have_version = true;
                }
                "arch" => m.arch = value,
                "abi" => {
                    m.abi = Abi::parse(&value).ok_or(Error::Format("unknown abi"))?;
                    have_abi = true;
                }
                "summary" => m.summary = value,
                "license" => m.license = value,
                "depends" => m.depends = list(&value).map(Dep::parse).collect::<Result<_, _>>()?,
                "permissions" => m.permissions = list(&value).map(String::from).collect(),
                "config" => {
                    m.config = list(&value).map(|p| String::from(p.trim_start_matches('/'))).collect();
                    if !m.config.iter().all(|p| crate::archive::valid_path(p)) {
                        return Err(Error::Format("bad config path"));
                    }
                }
                "essential" => m.essential = value == "yes",
                "installed-size" => m.installed_size = number(&value)?,
                "file" => m.file = value,
                "size" => m.size = number(&value)?,
                "sha256" => m.sha256 = value,
                // Unknown fields are kept out of the way for newer formats.
                _ => {}
            }
        }
        if !have_name || !have_version || !have_abi {
            return Err(Error::Format("manifest needs name, version and abi"));
        }
        Ok(m)
    }

    /// The paragraph text (index fields only when set).
    pub fn to_text(&self) -> String {
        let mut s =
            format!("name: {}\nversion: {}\narch: {}\nabi: {}\n", self.name, self.version, self.arch, self.abi.name());
        let mut add = |k: &str, v: &str| {
            if !v.is_empty() {
                s += &format!("{k}: {v}\n");
            }
        };
        add("summary", &self.summary);
        add("license", &self.license);
        add("depends", &self.depends.iter().map(Dep::to_string).collect::<Vec<_>>().join(", "));
        add("permissions", &self.permissions.join(", "));
        add("config", &self.config.join(", "));
        if self.essential {
            add("essential", "yes");
        }
        add("installed-size", &self.installed_size.to_string());
        add("file", &self.file);
        if self.size > 0 {
            add("size", &self.size.to_string());
        }
        add("sha256", &self.sha256);
        s
    }
}

fn number(s: &str) -> Result<u64, Error> {
    s.parse().map_err(|_| Error::Format("bad number"))
}

fn list(s: &str) -> impl Iterator<Item = &str> {
    s.split(',').map(str::trim).filter(|x| !x.is_empty())
}

/// The `key: value` lines of a paragraph (a line starting with a space
/// continues the previous value).
fn fields(text: &str) -> Result<Vec<(&str, String)>, Error> {
    let mut out: Vec<(&str, String)> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            let last = out.last_mut().ok_or(Error::Format("continuation without a field"))?;
            last.1.push(' ');
            last.1.push_str(line.trim());
            continue;
        }
        let (k, v) = line.split_once(':').ok_or(Error::Format("line without ':'"))?;
        out.push((k.trim(), v.trim().into()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let text = "name: hello\nversion: 1.1-1\narch: x86_64\nabi: linux\nsummary: Says hello\n\
                    depends: libgreet (>= 1.0), base\npermissions: network\nconfig: /etc/hello.conf, etc/hello.d/a\n\
                    installed-size: 1234\n";
        let m = Manifest::parse(text).unwrap();
        assert_eq!(m.depends[0], Dep { name: "libgreet".into(), op: Op::Ge, version: "1.0".into() });
        assert_eq!(m.depends[1].op, Op::Any);
        assert_eq!(m.abi, Abi::Linux);
        assert_eq!(m.config, ["etc/hello.conf", "etc/hello.d/a"]);
        assert_eq!(Manifest::parse(&m.to_text()).unwrap(), m);
        assert_eq!(m.file_name(), "hello-1.1-1.x86_64.qpk");
    }

    #[test]
    fn rejects_bad_manifests() {
        assert!(Manifest::parse("name: Hello\nversion: 1\nabi: any\n").is_err());
        assert!(Manifest::parse("name: hello\nabi: any\n").is_err());
        assert!(Manifest::parse("name: hello\nversion: 1\n").is_err());
        assert!(Manifest::parse("name: hello\nversion: 1\nabi: windows\n").is_err());
        assert!(Dep::parse("x (~ 1)").is_err());
        assert!(Dep::parse("../etc").is_err());
    }
}
