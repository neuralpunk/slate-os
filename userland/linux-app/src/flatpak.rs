// SPDX-License-Identifier: MIT OR Apache-2.0

//! Flatpak and AppImage on Slate (ADR 0114), the invisible bubble: apps
//! from Flathub run in Flatpak's own sandbox (bubblewrap) inside the Linux
//! runtime, and show as Strata windows. Flatpak, bubblewrap and OSTree
//! are Alpine's, in the runtime (ADR 0022: Linux software); this is
//! Slate's side.
//!
//! - `slate-flatpak install [--from REMOTE] APP...`: from Flathub (added
//!   if missing) or another remote, as the person (`--user`): no
//!   privilege.
//! - `slate-flatpak remote-add NAME URL|FILE`: another remote, from its
//!   description (a `.flatpakrepo`), which must name an https repository
//!   and carry its signing key; `remotes` lists them, `remote-delete NAME`
//!   removes one. `flathub` is Flathub's alone, with its pinned key.
//! - `slate-flatpak trust-key FINGERPRINT`: should Flathub replace its
//!   key, the person trusts the new one for their own installation
//!   (`~/.config/slate/flathub-keys`); an administrator can for everyone
//!   (`/etc/slate/flathub-keys`), a fingerprint a line.
//! - `slate-flatpak run APP [ARG...]`: in a Strata window.
//! - `slate-flatpak list`, `updates` (what has a newer version):
//!   application, name, version, branch, tab-separated.
//! - `slate-flatpak update [APP...]`: each app's version (its OSTree
//!   commit, signed by Flathub) is kept first in
//!   `~/.local/share/slate/flatpak-history`, then all are updated: one
//!   command, or one click in the Software Updater.
//! - `slate-flatpak rollback APP`: back to the newest kept version that is
//!   not the one installed, or, with none kept (an app updated by
//!   `flatpak update` itself), to the commit before the installed one in
//!   its remote's history (Flatpak fetches it, signature checked).
//! - `slate-flatpak remove APP...`.
//! - `slate-flatpak catalog`: Flathub (added if missing) and its
//!   catalog, fetched as Flatpak fetches it (`update --appstream`, signed
//!   with the repository), into the person's installation for App Center
//!   (ADR 0125): `~/.local/share/flatpak/appstream/flathub/x86_64/active`.
//! - `slate-flatpak --system install|remove|update|list|updates|remotes
//!   ...` (and root's `remote-add`, `remote-delete`): apps for every
//!   account, in the runtime's system installation (/var/lib/flatpak).
//!   Root runs flatpak itself (no system helper); anyone else asks the
//!   broker (`flatpak=`, approved as other system actions are), which
//!   runs this as root.
//!
//! `slate-appimage --add FILE` gives an AppImage a launcher entry in Strata
//! (`~/.local/share/strata/apps`, from the AppImage's own desktop entry);
//! `--list` shows the extracted ones and their sizes, `--remove FILE|ID`
//! removes one (and its entry), `--clean` those whose file is gone.
//!
//! `slate-appimage FILE [ARG...]` runs an AppImage: it is extracted once
//! (by its own runtime, `--appimage-extract`: no FUSE) into
//! `~/.cache/slate/appimages`, and its AppRun runs in Flatpak's sandbox on
//! the freedesktop runtime, which has the glibc AppImages are built for
//! (the Linux runtime is Alpine's musl), in a Strata window.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Where Flathub's description is (the remote is added from it).
pub const FLATHUB: &str = "https://dl.flathub.org/repo/flathub.flatpakrepo";
/// Flathub's repository, as its description must name it.
pub const FLATHUB_URL: &str = "https://dl.flathub.org/repo/";
/// Flathub's signing key, pinned by its OpenPGP fingerprint (`gpg
/// --show-keys` of the key in Flathub's description, 2026-10-24: "Flathub
/// Repo Signing Key"). The fingerprint stays when the key's expiry is
/// extended; flatpak checks every download against the key (ADR 0115).
pub const FLATHUB_KEY: &str = "6E5C05D979C76DAF93C081354184DD4D907A7CAE";
/// More fingerprints for Flathub's key: the administrator's, and the
/// person's (from their home).
pub const FLATHUB_KEYS_SYSTEM: &str = "/etc/slate/flathub-keys";
pub const FLATHUB_KEYS_PERSON: &str = ".config/slate/flathub-keys";
/// The runtime AppImages run on.
pub const APPIMAGE_RUNTIME: &str = "org.freedesktop.Platform//25.08";
/// Versions kept per app for a rollback.
const KEEP: usize = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cmd {
    /// From a remote (Flathub unless `--from` names another).
    Install(String, Vec<String>),
    /// A remote's name and where its description is (a URL or a file).
    RemoteAdd(String, String),
    Remotes,
    RemoteDelete(String),
    /// A fingerprint for Flathub's key, normalised.
    TrustKey(String),
    Run(Vec<String>),
    List,
    Updates,
    Update(Vec<String>),
    Rollback(String),
    Remove(Vec<String>),
    /// The installed apps, for the Software Updater: [`status`]'s lines.
    Status,
    /// `update --auto`: Strata's background update (ADR 0115), when it is
    /// on and due ([`auto_due`]).
    AutoUpdate,
    /// Flathub's catalog, fetched for App Center (ADR 0125).
    Catalog,
}

/// What `--system` does: the person's apps' history, rollbacks, status
/// and the background update stay with their own installation.
pub fn system_ok(c: &Cmd) -> bool {
    matches!(
        c,
        Cmd::Install(..)
            | Cmd::Remove(_)
            | Cmd::Update(_)
            | Cmd::List
            | Cmd::Updates
            | Cmd::Remotes
            | Cmd::RemoteAdd(..)
            | Cmd::RemoteDelete(_)
    )
}

/// The command, and whether it is for the system installation
/// (`--system` first).
pub fn parse_scoped(args: &[String]) -> Result<(Cmd, bool), String> {
    match args.split_first() {
        Some((first, rest)) if first == "--system" => {
            let c = parse(rest)?;
            if !system_ok(&c) {
                return Err(format!(
                    "--system: {} is for your own apps only",
                    rest.first().map(String::as_str).unwrap_or("")
                ));
            }
            Ok((c, true))
        }
        _ => parse(args).map(|c| (c, false)),
    }
}

pub const USAGE: &str = "usage: slate-flatpak install [--from REMOTE] APP... | run APP [ARG...] | list | updates | update [APP...] | rollback APP | remove APP... | status | catalog | update --auto | remote-add NAME URL|FILE | remotes | remote-delete NAME | trust-key FINGERPRINT; --system before install, remove, update, list, updates, remotes, remote-add or remote-delete: for every account";

/// An OpenPGP v4 fingerprint as people write it (spaces between groups,
/// any case): its 40 hexadecimal digits, upper case.
pub fn normal_fingerprint(text: &str) -> Option<String> {
    let hex: String = text.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_uppercase();
    (hex.len() == 40 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then_some(hex)
}

/// The fingerprints in a keys file, a line each (`#` comments).
pub fn parse_keys(text: &str) -> Vec<String> {
    text.lines().map(|l| l.split('#').next().unwrap_or("")).filter_map(normal_fingerprint).collect()
}

/// Flathub's name among the remotes.
pub const FLATHUB_NAME: &str = "flathub";

/// A remote's name: letters, digits, `.`, `_` and `-`, not starting with
/// `-` (flatpak's names are such).
pub fn remote_name_ok(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && !n.starts_with('-')
        && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// A Flatpak application ID (reverse DNS, at least three parts), or a
/// ref with a branch (`org.app.Name//stable`).
pub fn app_id_ok(id: &str) -> bool {
    let name = id.split("//").next().unwrap_or("");
    name.split('.').count() >= 3
        && name
            .split('.')
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        && id.chars().all(|c| !c.is_whitespace())
}

pub fn parse(args: &[String]) -> Result<Cmd, String> {
    let (cmd, rest) = args.split_first().ok_or(USAGE)?;
    let ids = |r: &[String]| -> Result<Vec<String>, String> {
        match r.iter().find(|a| !app_id_ok(a)) {
            Some(bad) => Err(format!("{bad}: not a Flatpak application ID (like org.mozilla.firefox)")),
            None => Ok(r.to_vec()),
        }
    };
    Ok(match (cmd.as_str(), rest) {
        ("install", [from, name, r @ ..]) if from == "--from" && !r.is_empty() => {
            if !remote_name_ok(name) {
                return Err(format!("{name}: not a remote's name"));
            }
            Cmd::Install(name.clone(), ids(r)?)
        }
        ("install", r) if !r.is_empty() => Cmd::Install(FLATHUB_NAME.into(), ids(r)?),
        ("remote-add", [name, at]) => {
            if !remote_name_ok(name) {
                return Err(format!("{name}: not a remote's name"));
            }
            if name == FLATHUB_NAME {
                return Err(String::from("flathub is Flathub's, added with its pinned key by install"));
            }
            Cmd::RemoteAdd(name.clone(), at.clone())
        }
        ("remotes", []) => Cmd::Remotes,
        ("remote-delete", [name]) if remote_name_ok(name) => Cmd::RemoteDelete(name.clone()),
        ("trust-key", words) if !words.is_empty() => {
            Cmd::TrustKey(normal_fingerprint(&words.join(" ")).ok_or("a key's fingerprint is 40 hexadecimal digits")?)
        }
        ("run", [app, ..]) => {
            ids(core::slice::from_ref(app))?;
            Cmd::Run(rest.to_vec())
        }
        ("list", []) => Cmd::List,
        ("updates", []) => Cmd::Updates,
        ("update", [auto]) if auto == "--auto" => Cmd::AutoUpdate,
        ("update", r) => Cmd::Update(ids(r)?),
        ("rollback", [app]) => Cmd::Rollback(ids(core::slice::from_ref(app))?.remove(0)),
        ("remove", r) if !r.is_empty() => Cmd::Remove(ids(r)?),
        ("status", []) => Cmd::Status,
        ("catalog", []) => Cmd::Catalog,
        _ => return Err(USAGE.into()),
    })
}

/// flatpak's arguments for each step (`--user`: the person's own
/// installation, with no system helper; [`argv::system`] turns one to
/// the system installation).
pub mod argv {
    use super::*;

    fn flatpak(words: &[&str]) -> Vec<String> {
        core::iter::once("/usr/bin/flatpak").chain(words.iter().copied()).map(String::from).collect()
    }

    /// Flathub, from its description as Slate fetched and checked it
    /// ([`super::check_flathub`]).
    /// Flathub's catalog (AppStream data, signed with the repository).
    pub fn catalog() -> Vec<String> {
        flatpak(&["--user", "update", "--appstream", "flathub"])
    }
    pub fn add_flathub(description: &str) -> Vec<String> {
        flatpak(&["--user", "remote-add", "--if-not-exists", "flathub", description])
    }
    pub fn install(from: &str, ids: &[String]) -> Vec<String> {
        let mut v = flatpak(&["--user", "install", "-y", "--noninteractive", from]);
        v.extend(ids.iter().cloned());
        v
    }
    /// Another remote, from its description as Slate checked it
    /// ([`super::check_description`]).
    pub fn add_remote(name: &str, description: &str) -> Vec<String> {
        flatpak(&["--user", "remote-add", "--if-not-exists", name, description])
    }
    pub fn remotes() -> Vec<String> {
        flatpak(&["--user", "remotes", "--columns=name,url"])
    }
    pub fn remote_delete(name: &str) -> Vec<String> {
        flatpak(&["--user", "remote-delete", name])
    }
    /// application, name, version, branch, and the deployed commit
    /// (shortened to 12 digits: [`show_commit`] has it whole).
    pub fn list() -> Vec<String> {
        flatpak(&["--user", "list", "--app", "--columns=application,name,version,branch,active"])
    }
    /// An installed app's whole deployed commit (`flatpak info`).
    pub fn show_commit(id: &str) -> Vec<String> {
        flatpak(&["--user", "info", "--show-commit", id])
    }
    pub fn updates() -> Vec<String> {
        flatpak(&["--user", "remote-ls", "--updates", "--app", "--columns=application,name,version,branch"])
    }
    pub fn update(ids: &[String]) -> Vec<String> {
        let mut v = flatpak(&["--user", "update", "-y", "--noninteractive"]);
        v.extend(ids.iter().cloned());
        v
    }
    /// The remote an installed app came from (`flatpak info`).
    pub fn origin(id: &str) -> Vec<String> {
        flatpak(&["--user", "info", "--show-origin", id])
    }
    /// The app's commits on its remote, newest first.
    pub fn remote_log(origin: &str, id: &str) -> Vec<String> {
        flatpak(&["--user", "remote-info", "--log", origin, id])
    }
    pub fn update_to(id: &str, commit: &str) -> Vec<String> {
        flatpak(&["--user", "update", "-y", "--noninteractive", &format!("--commit={commit}"), id])
    }
    pub fn remove(ids: &[String]) -> Vec<String> {
        let mut v = flatpak(&["--user", "uninstall", "-y", "--noninteractive"]);
        v.extend(ids.iter().cloned());
        v
    }
    /// The same step on the system installation.
    pub fn system(v: Vec<String>) -> Vec<String> {
        v.into_iter().map(|w| if w == "--user" { String::from("--system") } else { w }).collect()
    }
    pub fn run(args: &[String]) -> Vec<String> {
        let mut v = flatpak(&["run"]);
        v.extend(args.iter().cloned());
        v
    }
    /// An extracted AppImage's AppRun on the freedesktop runtime: the
    /// person's files (where it was put), the display, the GPU and the
    /// network, as AppImages expect.
    pub fn appimage(dir: &str, args: &[String]) -> Vec<String> {
        let mut v = flatpak(&[
            "run",
            "--filesystem=home",
            "--socket=wayland",
            "--socket=fallback-x11",
            "--device=dri",
            "--share=network",
            &format!("--command={dir}/AppRun"),
            APPIMAGE_RUNTIME,
        ]);
        v.extend(args.iter().cloned());
        v
    }
}

/// An installed app, as `list` gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    pub id: String,
    pub name: String,
    pub version: String,
    pub branch: String,
    pub commit: String,
}

/// `flatpak list` with [`argv::list`]'s columns.
pub fn parse_list(text: &str) -> Vec<Installed> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').map(str::trim).collect();
            let at = |i: usize| f.get(i).copied().unwrap_or("").to_string();
            app_id_ok(f.first()?).then(|| Installed {
                id: at(0),
                name: at(1),
                version: at(2),
                branch: at(3),
                commit: at(4),
            })
        })
        .collect()
}

/// The history: an app, a commit and when it was seen (seconds), a line
/// each, oldest first.
pub fn parse_history(text: &str) -> Vec<(String, String, i64)> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            Some((f.next()?.to_string(), f.next()?.to_string(), f.next()?.parse().ok()?))
        })
        .collect()
}

/// The history with the installed versions added (when they differ from
/// the app's last line), keeping [`KEEP`] per app.
pub fn record(history: &[(String, String, i64)], installed: &[Installed], now: i64) -> String {
    let mut h = history.to_vec();
    for i in installed.iter().filter(|i| !i.commit.is_empty()) {
        let last = h.iter().rev().find(|(a, _, _)| *a == i.id).map(|(_, c, _)| c.clone());
        if last.as_deref() != Some(i.commit.as_str()) {
            h.push((i.id.clone(), i.commit.clone(), now));
        }
    }
    // The newest KEEP of each app.
    let mut kept: Vec<(String, String, i64)> = Vec::new();
    for (i, e) in h.iter().enumerate() {
        let newer = h[i + 1..].iter().filter(|x| x.0 == e.0).count();
        if newer < KEEP {
            kept.push(e.clone());
        }
    }
    kept.iter().map(|(a, c, t)| format!("{a} {c} {t}\n")).collect()
}

/// The commit a rollback of `app` goes to: the newest kept one that isn't
/// `current`.
pub fn rollback_target(history: &[(String, String, i64)], app: &str, current: &str) -> Option<String> {
    history.iter().rev().find(|(a, c, _)| a == app && c != current).map(|(_, c, _)| c.clone())
}

/// The commits in `flatpak remote-info --log`'s output, newest first
/// (`Commit: HEX` lines).
pub fn parse_log(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("Commit:"))
        .map(str::trim)
        .filter(|c| c.len() == 64 && c.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(String::from)
        .collect()
}

/// The commit before `current` in a remote's log (newest first): where a
/// rollback goes when no earlier version was kept.
pub fn before_in_log(log: &[String], current: &str) -> Option<String> {
    let at = log.iter().position(|c| c == current || (current.len() >= 12 && c.starts_with(current)))?;
    log.get(at + 1).cloned()
}

/// The installed apps for the Software Updater, a line each, tab-separated:
/// ID, name, version, the newer version on offer (`-` if none, `new` if
/// the remote names none), and `yes` when there is an earlier version to
/// roll back to: kept, or on the app's remote (`remote_back`, the apps
/// whose remote has one).
pub fn status(
    installed: &[Installed],
    updates: &[Installed],
    history: &[(String, String, i64)],
    remote_back: &[String],
) -> String {
    installed
        .iter()
        .map(|i| {
            let new = match updates.iter().find(|u| u.id == i.id) {
                None => "-",
                Some(u) if u.version.is_empty() => "new",
                Some(u) => u.version.as_str(),
            };
            let back = if rollback_target(history, &i.id, &i.commit).is_some() || remote_back.contains(&i.id) {
                "yes"
            } else {
                "no"
            };
            let name = if i.name.is_empty() { i.id.as_str() } else { i.name.as_str() };
            format!("{}\t{name}\t{}\t{new}\t{back}\n", i.id, i.version)
        })
        .collect()
}

/// The person's choice about background updates, in their Strata
/// settings: `auto=off` turns them off (they are on unless it says so).
pub const AUTO_SETTINGS: &str = ".config/strata/app-updates";
/// The background updates' log, a line per run: when (seconds), and what
/// happened. Its last line is the last run.
pub const AUTO_LOG: &str = ".cache/slate/app-updates.log";
/// How often background updates run (seconds).
pub const AUTO_EVERY_S: i64 = 6 * 3600;

/// Whether background updates are on, from the settings file's text.
pub fn auto_on(settings: &str) -> bool {
    !settings.lines().any(|l| l.trim() == "auto=off")
}

/// When the log's last run was (seconds), if it has one.
pub fn auto_last(log: &str) -> Option<i64> {
    log.lines().rev().find_map(|l| l.split_whitespace().next()?.parse().ok())
}

/// Whether a background update is due at `now`.
pub fn auto_due(settings: &str, log: &str, now: i64) -> bool {
    auto_on(settings) && auto_last(log).is_none_or(|t| now - t >= AUTO_EVERY_S || t > now)
}

/// The log with a run added (the newest 50 kept).
pub fn auto_logged(log: &str, now: i64, what: &str) -> String {
    let mut lines: Vec<&str> = log.lines().collect();
    let line = format!("{now} {}", what.replace('\n', " "));
    lines.push(&line);
    let from = lines.len().saturating_sub(50);
    lines[from..].iter().map(|l| format!("{l}\n")).collect()
}

/// The v4 fingerprint of the primary key in an OpenPGP key (RFC 4880
/// §12.2: SHA-1 of 0x99, the key packet's body length in two octets, and
/// the body), from the first packet, which must be a public key (tag 6,
/// §5.5.1.1) of version 4 (§5.5.2).
pub fn fingerprint(key: &[u8]) -> Option<[u8; 20]> {
    let first = *key.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    // Packet headers (§4.2): the new format (bit 6) or the old one.
    let (tag, len, at) = if first & 0x40 != 0 {
        let o1 = *key.get(1)? as usize;
        match o1 {
            0..192 => (first & 0x3f, o1, 2),
            192..224 => (first & 0x3f, ((o1 - 192) << 8) + *key.get(2)? as usize + 192, 3),
            255 => (first & 0x3f, u32::from_be_bytes(key.get(2..6)?.try_into().ok()?) as usize, 6),
            _ => return None,
        }
    } else {
        let tag = (first >> 2) & 0x0f;
        match first & 3 {
            0 => (tag, *key.get(1)? as usize, 2),
            1 => (tag, u16::from_be_bytes(key.get(1..3)?.try_into().ok()?) as usize, 3),
            2 => (tag, u32::from_be_bytes(key.get(1..5)?.try_into().ok()?) as usize, 5),
            _ => return None,
        }
    };
    let body = key.get(at..at + len)?;
    if tag != 6 || body.first() != Some(&4) || len > 0xffff {
        return None;
    }
    let mut h = slate_hash::Sha1::new();
    h.update(&[0x99, (len >> 8) as u8, len as u8]);
    h.update(body);
    Some(h.finish())
}

/// A field of a description (key file format: `Key=value`).
fn field<'a>(text: &'a str, k: &str) -> Option<&'a str> {
    text.lines().find_map(|l| l.strip_prefix(k)?.strip_prefix('=')).map(str::trim)
}

/// Check a remote's description (a .flatpakrepo, key file format): it
/// names an https repository and carries an OpenPGP signing key, which
/// flatpak then checks every download against. Its repository and the
/// key's fingerprint (hexadecimal, upper case).
pub fn check_description(text: &str) -> Result<(String, String), String> {
    if !text.lines().any(|l| l.trim() == "[Flatpak Repo]") {
        return Err(String::from("not a Flatpak repository's description (no [Flatpak Repo])"));
    }
    let url = field(text, "Url").ok_or("the description names no repository")?;
    if !url.starts_with("https://") {
        return Err(format!("{url}: only https repositories"));
    }
    let key = field(text, "GPGKey").and_then(slate_tls::pem::base64).ok_or("the description carries no signing key")?;
    let fp = fingerprint(&key).ok_or("the description's key isn't an OpenPGP key")?;
    Ok((String::from(url), fp.iter().map(|b| format!("{b:02X}")).collect()))
}

/// Check Flathub's description: it names Flathub's repository and carries
/// the pinned key, or one of `also` (the keys files').
pub fn check_flathub(text: &str, also: &[String]) -> Result<(), String> {
    if field(text, "Url") != Some(FLATHUB_URL) {
        return Err(format!(
            "Flathub's description names another repository ({})",
            field(text, "Url").unwrap_or("none")
        ));
    }
    let (_, fp) = check_description(text).map_err(|e| format!("Flathub's description: {e}"))?;
    if fp != FLATHUB_KEY && !also.contains(&fp) {
        return Err(format!(
            "Flathub's key is {fp}, not the one Slate trusts ({FLATHUB_KEY}). If Flathub has announced a new key \
             with that fingerprint, `slate-flatpak trust-key {fp}` trusts it for your apps (an administrator: \
             {FLATHUB_KEYS_SYSTEM})"
        ));
    }
    Ok(())
}

/// Whether `head` (a file's first bytes) is an AppImage: an ELF with the
/// AppImage magic "AI" and its type (1 or 2) at offset 8 (the AppImage
/// specification).
pub fn is_appimage(head: &[u8]) -> bool {
    head.len() >= 11 && head[..4] == *b"\x7fELF" && head[8..10] == *b"AI" && matches!(head[10], 1 | 2)
}

/// Whether an AppImage's desktop entry says it runs in a terminal
/// (`Terminal=true` in `[Desktop Entry]`, the Desktop Entry
/// Specification): then it runs on the terminal it was started from, not
/// in a window.
pub fn desktop_terminal(text: &str) -> bool {
    let mut entry = false;
    for l in text.lines().map(str::trim) {
        if l.starts_with('[') {
            entry = l == "[Desktop Entry]";
        } else if entry && let Some(v) = l.strip_prefix("Terminal").and_then(|v| v.trim_start().strip_prefix('=')) {
            return v.trim() == "true";
        }
    }
    false
}

/// Where Strata finds the person's own launcher entries.
pub const PERSON_APPS: &str = ".local/share/strata/apps";
/// In an extraction's directory: the AppImage it came from.
pub const APPIMAGE_SOURCE: &str = ".slate-source";

/// A key's value in a desktop entry's `[Desktop Entry]` group.
pub fn desktop_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let mut entry = false;
    for l in text.lines().map(str::trim) {
        if l.starts_with('[') {
            entry = l == "[Desktop Entry]";
        } else if entry
            && let Some((k, v)) = l.split_once('=')
            && k.trim() == key
        {
            return Some(v.trim());
        }
    }
    None
}

/// Strata's launcher entry (`.app`) for the AppImage extracted as `id`,
/// from its desktop entry: its name (else `fallback`), comment and first
/// category Strata groups by; it runs through `slate-appimage --entry`.
pub fn appimage_entry(id: &str, desktop: &str, fallback: &str) -> String {
    let name = desktop_value(desktop, "Name").filter(|n| !n.is_empty()).unwrap_or(fallback);
    let comment = desktop_value(desktop, "Comment").unwrap_or("");
    let category = desktop_value(desktop, "Categories")
        .and_then(|c| {
            c.split(';').find_map(|c| match c {
                "Network" | "WebBrowser" => Some("internet"),
                "Office" => Some("office"),
                "Graphics" => Some("graphics"),
                "AudioVideo" | "Audio" | "Video" => Some("sound & video"),
                "Development" => Some("development"),
                "Game" => Some("games"),
                "Utility" => Some("accessories"),
                _ => None,
            })
        })
        .unwrap_or("other");
    let one_line = |s: &str| s.replace(['\n', '\r'], " ");
    format!(
        "# An AppImage (slate-appimage --add).\nname={}\nexec=/bin/slate-appimage --entry {id}\nkind=app\nlinux=yes\ncategory={category}\ncomment={}\n",
        one_line(name),
        one_line(comment)
    )
}

/// Where an AppImage is extracted: by a name of its contents' hash.
pub fn extract_dir(home: &str, digest: &[u8]) -> String {
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("{home}/.cache/slate/appimages/{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn background_updates() {
        assert!(auto_on("") && auto_on("auto=on\n") && !auto_on("auto=off\n"));
        assert_eq!(auto_last(""), None);
        let log = auto_logged("", 1000, "updated");
        assert_eq!(log, "1000 updated\n");
        assert_eq!(auto_last(&auto_logged(&log, 2000, "failed: no network")), Some(2000));
        // Due the first time, then six hours on; never when off; again
        // if the clock went back.
        assert!(auto_due("", "", 5));
        assert!(!auto_due("", &log, 1000 + AUTO_EVERY_S - 1));
        assert!(auto_due("", &log, 1000 + AUTO_EVERY_S));
        assert!(!auto_due("auto=off\n", "", 5));
        assert!(auto_due("", &log, 10));
        let mut long = String::new();
        for i in 0..60 {
            long = auto_logged(&long, i, "x");
        }
        assert_eq!(long.lines().count(), 50);
        assert_eq!(parse(&s(&["update", "--auto"])), Ok(Cmd::AutoUpdate));
    }

    #[test]
    fn system_installation() {
        let one = || vec![String::from("org.app.One")];
        assert_eq!(parse_scoped(&s(&["install", "org.app.One"])), Ok((Cmd::Install("flathub".into(), one()), false)));
        assert_eq!(
            parse_scoped(&s(&["--system", "install", "org.app.One"])),
            Ok((Cmd::Install("flathub".into(), one()), true))
        );
        assert_eq!(parse_scoped(&s(&["--system", "remove", "org.app.One"])), Ok((Cmd::Remove(one()), true)));
        assert_eq!(parse_scoped(&s(&["--system", "update"])), Ok((Cmd::Update(vec![]), true)));
        assert_eq!(parse_scoped(&s(&["--system", "list"])), Ok((Cmd::List, true)));
        for own in [&["rollback", "org.app.One"][..], &["status"], &["update", "--auto"], &["run", "org.app.One"]] {
            let mut a = vec!["--system"];
            a.extend_from_slice(own);
            assert!(parse_scoped(&s(&a)).is_err(), "{own:?} is the person's");
        }
        assert!(parse_scoped(&s(&["--system"])).is_err());
        assert_eq!(
            argv::system(argv::install("flathub", &one())),
            s(&["/usr/bin/flatpak", "--system", "install", "-y", "--noninteractive", "flathub", "org.app.One"])
        );
        assert_eq!(argv::system(argv::run(&one())), argv::run(&one()), "run finds both installations");
    }

    #[test]
    fn flathub_pinned() {
        let real = include_str!("../tests/flathub.flatpakrepo");
        assert_eq!(check_flathub(real, &[]), Ok(()));
        // Another repository, or another key, is refused.
        assert!(check_flathub(&real.replace("dl.flathub.org", "evil.example"), &[]).is_err());
        let key = real.lines().find_map(|l| l.strip_prefix("GPGKey=")).unwrap();
        let mut bytes = slate_tls::pem::base64(key).unwrap();
        bytes[20] ^= 1;
        assert!(fingerprint(&bytes).is_some());
        let other = real.replace(key, &b64(&bytes));
        let refused = check_flathub(&other, &[]).unwrap_err();
        assert!(refused.contains("not the one Slate trusts") && refused.contains("slate-flatpak trust-key"));
        assert!(check_flathub("[Flatpak Repo]\nUrl=https://dl.flathub.org/repo/\n", &[]).is_err());
        // A replaced key, trusted by fingerprint (as Flathub would print
        // it, in groups), is accepted.
        let fp: String = fingerprint(&bytes).unwrap().iter().map(|b| format!("{b:02x} ")).collect();
        let keys = parse_keys(&format!("# Flathub's new key\n{fp}\nnot a key\n"));
        assert_eq!(keys.len(), 1);
        assert_eq!(check_flathub(&other, &keys), Ok(()));
        assert_eq!(
            parse(&s(&["trust-key", "6E5C 05D9 79C7 6DAF 93C0", "8135 4184 DD4D 907A 7CAE"])),
            Ok(Cmd::TrustKey(FLATHUB_KEY.into()))
        );
        assert!(parse(&s(&["trust-key", "1234"])).is_err());
        // Another remote: https and a key, whatever the key.
        let (url, fp) = check_description(&other.replace("dl.flathub.org", "flatpak.example.org")).unwrap();
        assert_eq!(url, "https://flatpak.example.org/repo/");
        assert_eq!(fp.len(), 40);
        assert!(check_description(&real.replace("https://", "http://")).unwrap_err().contains("only https"));
        assert!(check_description("[Flatpak Repo]\nUrl=https://x.example/\n").unwrap_err().contains("no signing key"));
        assert!(check_description("Url=https://x.example/\n").is_err());
        // A packet shorter than its length, and a signature packet (tag 2).
        assert_eq!(fingerprint(&[0x99, 0, 9, 4]), None);
        assert_eq!(fingerprint(&[0x89, 0, 1, 4]), None);
    }

    fn b64(b: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in b.chunks(3) {
            let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
            for i in 0..4 {
                s.push(if i <= c.len() { A[(n >> (18 - 6 * i)) as usize & 63] as char } else { '=' });
            }
        }
        s
    }

    #[test]
    fn terminal_appimages() {
        assert!(desktop_terminal("[Desktop Entry]\nName=appimagetool\nTerminal = true\n"));
        assert!(!desktop_terminal("[Desktop Entry]\nName=App\nTerminal=false\n[Desktop Action x]\nTerminal=true\n"));
        assert!(!desktop_terminal("[Desktop Entry]\nName=App\n"));
        let installed = [
            Installed {
                id: "a.b.C".into(),
                name: "C".into(),
                version: "1".into(),
                branch: "stable".into(),
                commit: "c2".into(),
            },
            Installed {
                id: "d.e.F".into(),
                name: "".into(),
                version: "".into(),
                branch: "stable".into(),
                commit: "f1".into(),
            },
        ];
        let offered = [Installed {
            id: "a.b.C".into(),
            name: "C".into(),
            version: "2".into(),
            branch: "stable".into(),
            commit: "".into(),
        }];
        let h = parse_history("a.b.C c1 10\na.b.C c2 20\nd.e.F f1 20\n");
        assert_eq!(status(&installed, &offered, &h, &[]), "a.b.C\tC\t1\t2\tyes\nd.e.F\td.e.F\t\t-\tno\n");
        let on_remote = ["d.e.F".to_string()];
        assert!(status(&installed, &offered, &h, &on_remote).ends_with("d.e.F\td.e.F\t\t-\tyes\n"));
    }

    #[test]
    fn commands() {
        assert_eq!(parse(&s(&["status"])), Ok(Cmd::Status));
        assert_eq!(parse(&s(&["catalog"])), Ok(Cmd::Catalog));
        assert!(parse(&s(&["catalog", "now"])).is_err());
        assert_eq!(
            parse(&s(&["install", "fi.skyjake.Lagrange"])),
            Ok(Cmd::Install("flathub".into(), s(&["fi.skyjake.Lagrange"])))
        );
        assert_eq!(
            parse(&s(&["install", "--from", "gnome-nightly", "org.gnome.Maps"])),
            Ok(Cmd::Install("gnome-nightly".into(), s(&["org.gnome.Maps"])))
        );
        assert!(parse(&s(&["install", "--from", "-x", "org.gnome.Maps"])).is_err());
        assert_eq!(
            parse(&s(&["remote-add", "kde", "https://cdn.kde.org/flatpak/kde.flatpakrepo"])),
            Ok(Cmd::RemoteAdd("kde".into(), "https://cdn.kde.org/flatpak/kde.flatpakrepo".into()))
        );
        assert!(parse(&s(&["remote-add", "flathub", "https://x.example/x.flatpakrepo"])).is_err());
        assert!(parse(&s(&["remote-add", "a b", "x"])).is_err());
        assert_eq!(parse(&s(&["remotes"])), Ok(Cmd::Remotes));
        assert_eq!(parse(&s(&["remote-delete", "kde"])), Ok(Cmd::RemoteDelete("kde".into())));
        assert_eq!(
            parse(&s(&["run", "org.mozilla.firefox", "--new-window"])),
            Ok(Cmd::Run(s(&["org.mozilla.firefox", "--new-window"])))
        );
        assert_eq!(parse(&s(&["update"])), Ok(Cmd::Update(vec![])));
        assert_eq!(parse(&s(&["rollback", "org.app.Name//stable"])), Ok(Cmd::Rollback("org.app.Name//stable".into())));
        assert!(parse(&s(&["install", "--system"])).is_err());
        assert!(parse(&s(&["install", "firefox"])).is_err(), "not an ID");
        assert!(parse(&s(&["install", "org.x.y; rm"])).is_err());
        assert!(parse(&s(&["frobnicate"])).is_err());
        assert_eq!(argv::install("flathub", &s(&["a.b.C"]))[1..4], s(&["--user", "install", "-y"])[..]);
        assert_eq!(argv::install("kde", &s(&["a.b.C"]))[5..], s(&["kde", "a.b.C"])[..]);
        let a = argv::appimage("/home/ada/.cache/slate/appimages/x/squashfs-root", &s(&["--x"]));
        assert!(a.contains(&"--command=/home/ada/.cache/slate/appimages/x/squashfs-root/AppRun".into()));
        assert_eq!(a.last().map(String::as_str), Some("--x"));
    }

    #[test]
    fn lists_history_and_rollbacks() {
        let list = "fi.skyjake.Lagrange\tLagrange\t1.18.5\tstable\t8232c73f0a97\nnot an id\tx\n";
        let apps = parse_list(list);
        assert_eq!(apps.len(), 1);
        assert_eq!((apps[0].version.as_str(), apps[0].commit.as_str()), ("1.18.5", "8232c73f0a97"));
        // Recorded before each update; a repeat adds nothing.
        let h1 = record(&[], &apps, 100);
        assert_eq!(h1, "fi.skyjake.Lagrange 8232c73f0a97 100\n");
        assert_eq!(record(&parse_history(&h1), &apps, 200), h1);
        let newer = vec![Installed { commit: "99aa".into(), ..apps[0].clone() }];
        let h2 = record(&parse_history(&h1), &newer, 300);
        let h = parse_history(&h2);
        assert_eq!(rollback_target(&h, "fi.skyjake.Lagrange", "99aa").as_deref(), Some("8232c73f0a97"));
        assert_eq!(rollback_target(&h, "fi.skyjake.Lagrange", "8232c73f0a97").as_deref(), Some("99aa"));
        assert_eq!(rollback_target(&h, "org.other.App", "x"), None);
        // An app updated outside slate-flatpak: its remote's log.
        let log = parse_log(include_str!("../tests/remote-log.txt"));
        assert_eq!(log.len(), 6);
        assert_eq!(
            before_in_log(&log, "bd08625d1c6456f7f177007537cca81ba9f427dbe5ecf008806daec83fd38dea").as_deref(),
            Some("523871b4c948f91b6c04bf2c9e1c8a6ccb7e0507fe1c0a0a1d5d1d0c588487e2")
        );
        assert_eq!(before_in_log(&log, "523871b4c948").as_deref(), Some(log[2].as_str()), "a short commit");
        assert_eq!(before_in_log(&log, &log[5]), None, "the oldest shown");
        assert_eq!(before_in_log(&log, "ffff"), None);
        // Only the newest five per app stay.
        let mut many = Vec::new();
        for i in 0..8 {
            many.push(("a.b.C".to_string(), format!("c{i}"), i));
        }
        let kept = parse_history(&record(&many, &[], 9));
        assert_eq!(kept.len(), 5);
        assert_eq!(kept[0].1, "c3");
    }

    #[test]
    fn appimages() {
        let mut head = vec![0u8; 16];
        head[..4].copy_from_slice(b"\x7fELF");
        assert!(!is_appimage(&head));
        head[8..11].copy_from_slice(b"AI\x02");
        assert!(is_appimage(&head));
        assert!(!is_appimage(&head[..10]));
        assert_eq!(extract_dir("/home/ada", &[0xab; 32]), "/home/ada/.cache/slate/appimages/abababababababab");
        let d = "[Desktop Entry]\nName=Kdenlive\nComment=Edit videos\nCategories=Qt;AudioVideo;Video;\n[Desktop Action x]\nName=Other\n";
        assert_eq!(
            appimage_entry("0123456789abcdef", d, "x"),
            "# An AppImage (slate-appimage --add).\nname=Kdenlive\nexec=/bin/slate-appimage --entry 0123456789abcdef\nkind=app\nlinux=yes\ncategory=sound & video\ncomment=Edit videos\n"
        );
        assert!(appimage_entry("ab", "", "tool.AppImage").contains("name=tool.AppImage\n"));
    }
}
