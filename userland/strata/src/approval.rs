// SPDX-License-Identifier: MIT OR Apache-2.0

//! The system approval dialog's state (docs/design/WM_STYLE.md §6, ADR 0035,
//! ADR 0037): what is asked, by whom, the password being typed, the focus
//! and the last error. It traps the keyboard while open: Enter approves,
//! Esc cancels, Tab moves between the field and the buttons.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_display::input::Mods;
use slate_ui::edit::LineEdit;

use crate::draw::{Approval, ApprovalFocus};

/// Where the request came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The broker asked (another program wants the action).
    Agent,
    /// Strata's own launcher.
    Launcher,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Dialog {
    pub origin: Origin,
    /// The broker's name for the action: restart, poweroff, rollback.
    pub action: String,
    pub requester: String,
    pub user: String,
    /// The password typed (ADR 0101's line editor: the caret moves).
    pub password: LineEdit,
    pub focus: ApprovalFocus,
    pub focus_visible: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Approve(String),
    Cancel,
}

impl Dialog {
    pub fn new(origin: Origin, action: &str, requester: &str, user: &str) -> Dialog {
        Dialog {
            origin,
            action: String::from(action),
            requester: String::from(requester),
            user: String::from(user),
            password: LineEdit::new("").with_max(256).secret(),
            focus: ApprovalFocus::Password,
            focus_visible: false,
            error: None,
        }
    }

    /// The title, the body, and the detail well's "change" row.
    pub fn texts(&self) -> (&'static str, String, String) {
        let who = &self.requester;
        match self.action.as_str() {
            "restart" => (
                "Restart the computer",
                format!("{who} wants to restart the computer. Open windows will close."),
                "restart".into(),
            ),
            "poweroff" => (
                "Power off the computer",
                format!("{who} wants to power off the computer. Open windows will close."),
                "power off".into(),
            ),
            a if a.starts_with("network=") => (
                "Change the network settings",
                format!("{who} wants to change how this computer connects to the network."),
                String::from(&a["network=".len()..]),
            ),
            "desktop=remove" => (
                "Remove Strata",
                format!("{who} wants to remove Strata. Logins after this session are on the text console."),
                "remove slate-desktop".into(),
            ),
            "desktop=add" => (
                "Add Strata",
                format!("{who} wants to add Strata, the desktop, from this system's own repository."),
                "install slate-desktop".into(),
            ),
            // ADR 0173's notice (ADR 0157's, with what it brings today).
            "graphics=full" => (
                slate_display::graphics::TITLE,
                format!("{who} wants to turn on full graphics. {}", slate_display::graphics::NOTICE),
                "install slate-firmware-gpu".into(),
            ),
            "graphics=slate" => (
                "SlateOS only",
                format!(
                    "{who} wants to stop loading AMD's firmware. From the next start the card shows one display at \
                     the resolution the computer starts with."
                ),
                "remove slate-firmware-gpu".into(),
            ),
            a if a.starts_with("user=") => {
                let words: Vec<&str> = a["user=".len()..].splitn(4, ' ').collect();
                let name = words.get(1).copied().unwrap_or("?");
                match words[0] {
                    "add" => {
                        let kind =
                            if words.get(2) == Some(&"admin") { "an administrator" } else { "a standard account" };
                        let full = words.get(3).filter(|f| !f.is_empty()).map_or(String::new(), |f| format!("{f}, "));
                        (
                            "Add an account",
                            format!("{who} wants to add an account for {full}{name}, as {kind}."),
                            format!("add {name}"),
                        )
                    }
                    "remove" => (
                        "Remove an account",
                        format!("{who} wants to remove the account {name} and its home folder, with every file in it."),
                        format!("remove {name}"),
                    ),
                    "admin" => (
                        "Make an administrator",
                        format!("{who} wants to let {name} administer this computer."),
                        format!("{name}: administrator"),
                    ),
                    "standard" => (
                        "Make a standard account",
                        format!("{who} wants {name} to stop administering this computer."),
                        format!("{name}: standard"),
                    ),
                    _ => (
                        "Change a password",
                        format!("{who} wants to change the password of {name}."),
                        format!("{name}: new password"),
                    ),
                }
            }
            "compat=on" => (
                "Turn on Linux compatibility",
                format!("{who} wants to let Linux programs run on this computer, apart from Slate's own."),
                "linux compatibility on".into(),
            ),
            "compat=off" => (
                "Turn off Linux compatibility",
                format!("{who} wants to stop Linux programs running on this computer. Any running now will stop."),
                "linux compatibility off".into(),
            ),
            a if a.starts_with("disk=") => {
                // The words of slate_diskutil (ADR 0112).
                let w: Vec<&str> = a["disk=".len()..].split(' ').collect();
                let at = |i: usize| w.get(i).copied().unwrap_or("?");
                let format = |f: &str| match f {
                    "fat32" => " as FAT32",
                    "slatefs" => " as SlateFS",
                    _ => "",
                };
                match w[0] {
                    "table" => (
                        "Erase a disk",
                        format!(
                            "{who} wants to erase {} and give it a new, empty partition table. Everything on it is lost.",
                            at(1)
                        ),
                        format!("erase {}", at(1)),
                    ),
                    "add" => (
                        "Add a partition",
                        format!("{who} wants to add a {} MiB partition to {}{}.", at(3), at(1), format(at(4))),
                        format!("new partition on {}", at(1)),
                    ),
                    "format" => (
                        "Format a partition",
                        format!("{who} wants to format {}{}. Everything on it is lost.", at(1), format(at(2))),
                        format!("format {}", at(1)),
                    ),
                    _ => (
                        "Delete a partition",
                        format!("{who} wants to delete the partition {}. What is on it is lost.", at(1)),
                        format!("delete {}", at(1)),
                    ),
                }
            }
            "update=install" => (
                "Install updates",
                format!(
                    "{who} wants to install the updates the repositories offer. They go into a new system that starts \
                     next time, and into this one; the system as it is now is kept to go back to."
                ),
                "quarry upgrade".into(),
            ),
            "browser=setup" => (
                "Set up the web browser",
                format!(
                    "{who} wants to let Linux programs run on this computer and set up the Linux runtime with \
                     Flatpak, so a web browser from Flathub can run in a sandbox of its own. It fetches a few \
                     hundred megabytes."
                ),
                "linux runtime with flatpak".into(),
            ),
            "flatpak=setup" => (
                "Set up apps from Flathub",
                format!(
                    "{who} wants to let Linux programs run on this computer and set up the Linux runtime with \
                     Flatpak, so apps from Flathub can run, each in a sandbox of its own. It fetches a few \
                     hundred megabytes."
                ),
                "linux runtime with flatpak".into(),
            ),
            a if a.starts_with("flatpak=") => {
                let words: Vec<&str> = a["flatpak=".len()..].split(' ').collect();
                let apps: Vec<&str> = words.iter().skip(1).copied().filter(|w| !w.starts_with("--")).collect();
                let (from, apps): (String, Vec<&str>) = match (words.get(1), words.get(2)) {
                    (Some(&"--from"), Some(remote)) => {
                        (format!("the remote {remote}"), apps.into_iter().skip(1).collect())
                    }
                    _ => ("Flathub".into(), apps),
                };
                let list = apps.join(", ");
                match words.first().copied() {
                    Some("install") => (
                        "Install an app for everyone",
                        format!("{who} wants to install {list} from {from} for every account on this computer."),
                        format!("flatpak --system install {list}"),
                    ),
                    Some("remove") => (
                        "Remove an app for everyone",
                        format!("{who} wants to remove {list}, installed for every account on this computer."),
                        format!("flatpak --system remove {list}"),
                    ),
                    _ if apps.is_empty() => (
                        "Update apps for everyone",
                        format!("{who} wants to update the apps installed for every account on this computer."),
                        "flatpak --system update".into(),
                    ),
                    _ => (
                        "Update apps for everyone",
                        format!("{who} wants to update {list}, installed for every account on this computer."),
                        format!("flatpak --system update {list}"),
                    ),
                }
            }
            "update=check" => (
                "Check for updates",
                format!("{who} wants to fetch the repositories' lists of packages."),
                "quarry update".into(),
            ),
            a if a.starts_with("end=") => {
                let (pid, sig) = a["end=".len()..].split_once(' ').unwrap_or(("?", "TERM"));
                let name = slate_rt::fs::read_file(format!("/proc/{pid}/comm").as_bytes())
                    .map(|c| String::from(slate_rt::lossy(&c).trim()))
                    .unwrap_or_default();
                let what = if name.is_empty() { format!("process {pid}") } else { format!("{name} (process {pid})") };
                let how = if sig == "KILL" { "stop at once" } else { "end" };
                (
                    "End a process",
                    format!(
                        "{who} wants to {how} {what}, which belongs to another account. Work it hasn't saved is lost."
                    ),
                    format!("end {pid}"),
                )
            }
            a if a.starts_with("timezone=") => (
                "Change the time zone",
                format!("{who} wants to change the computer's time zone. Clocks for everyone on it will follow."),
                String::from(&a["timezone=".len()..]),
            ),
            _ => (
                "Roll back the system",
                format!(
                    "{who} wants to start the previous system image at the next boot. The current one is kept as a \
                     snapshot, so you can return to it."
                ),
                "previous system image".into(),
            ),
        }
    }

    /// Handle a key (evdev code and character); Some when it decides.
    pub fn key(&mut self, code: u16, ch: Option<char>, mods: Mods) -> Option<Outcome> {
        match code {
            // Esc.
            1 => return Some(Outcome::Cancel),
            // Enter: the focused button, or approve from the field.
            28 | 96 => {
                return Some(match self.focus {
                    ApprovalFocus::Cancel => Outcome::Cancel,
                    _ => {
                        let pw = self.password.text();
                        self.password.wipe();
                        Outcome::Approve(pw)
                    }
                });
            }
            // Tab: field, Cancel, Approve.
            15 => {
                self.focus = match self.focus {
                    ApprovalFocus::Password => ApprovalFocus::Cancel,
                    ApprovalFocus::Cancel => ApprovalFocus::Approve,
                    ApprovalFocus::Approve => ApprovalFocus::Password,
                };
                self.focus_visible = true;
            }
            _ if self.focus == ApprovalFocus::Password => {
                let plain = !mods.ctrl && !mods.alt && !mods.logo;
                crate::lock::edit_field(&mut self.password, code, ch, mods.shift, mods.ctrl, plain);
            }
            _ => {}
        }
        None
    }

    /// A wrong password: say so and start again.
    pub fn retry(&mut self, error: &str) {
        self.password.wipe();
        self.focus = ApprovalFocus::Password;
        self.error = Some(String::from(error));
    }

    /// Draw it with this view.
    pub fn view<'a>(&'a self, body: &'a str, details: &'a [(&'a str, &'a str)]) -> Approval<'a> {
        Approval {
            title: self.texts().0,
            body,
            details,
            user: &self.user,
            password: &self.password,
            focus: self.focus,
            focus_visible: self.focus_visible,
            error: self.error.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_and_compat_texts() {
        let t = |a: &str| Dialog::new(Origin::Agent, a, "strata-settings", "ada").texts();
        let (title, body, change) = t("user=add grace admin Grace Hopper");
        assert_eq!(title, "Add an account");
        assert_eq!(body, "strata-settings wants to add an account for Grace Hopper, grace, as an administrator.");
        assert_eq!(change, "add grace");
        assert_eq!(
            t("user=add bo standard").1,
            "strata-settings wants to add an account for bo, as a standard account."
        );
        assert_eq!(t("user=remove bo").0, "Remove an account");
        assert_eq!(t("user=standard bo").2, "bo: standard");
        assert_eq!(t("user=password bo").0, "Change a password");
        assert_eq!(t("compat=off").0, "Turn off Linux compatibility");
        // The system tools' (ADR 0112).
        assert_eq!(
            t("disk=table sdb").1,
            "strata-settings wants to erase sdb and give it a new, empty partition table. Everything on it is lost."
        );
        assert_eq!(
            t("disk=add sdb 1 100 fat32 Photos").1,
            "strata-settings wants to add a 100 MiB partition to sdb as FAT32."
        );
        assert_eq!(t("disk=format sdb1 slatefs").2, "format sdb1");
        assert_eq!(t("disk=delete sdb1").0, "Delete a partition");
        assert_eq!(t("update=install").0, "Install updates");
        assert_eq!(t("browser=setup").0, "Set up the web browser");
        assert_eq!(
            t("flatpak=install --from mine org.app.One org.app.Two").1,
            "strata-settings wants to install org.app.One, org.app.Two from the remote mine for every account on this computer."
        );
        assert_eq!(
            t("flatpak=install org.app.One").1,
            "strata-settings wants to install org.app.One from Flathub for every account on this computer."
        );
        assert_eq!(t("flatpak=remove org.app.One").0, "Remove an app for everyone");
        assert_eq!(t("flatpak=update").2, "flatpak --system update");
        assert_eq!(
            t("end=999999 KILL").1,
            "strata-settings wants to stop at once process 999999, which belongs to another account. Work it hasn't saved is lost."
        );
        assert_eq!(t("rollback").0, "Roll back the system");
    }

    #[test]
    fn keyboard() {
        let mut d = Dialog::new(Origin::Agent, "restart", "slate-approve", "tester");
        let m = Mods::default();
        for c in "pw1".chars() {
            assert_eq!(d.key(0, Some(c), m), None);
        }
        d.key(14, None, m);
        assert_eq!(d.password.text(), "pw");
        // The caret moves: a letter typed in the middle.
        d.key(slate_display::input::KEY_LEFT, None, m);
        d.key(0, Some('a'), m);
        assert_eq!(d.key(28, None, m), Some(Outcome::Approve("paw".into())));
        assert!(d.password.is_empty(), "wiped once sent");
        d.retry("That password didn't work. Try again.");
        assert!(d.password.is_empty() && d.error.is_some());
        d.key(15, None, m);
        assert_eq!(d.key(28, None, m), Some(Outcome::Cancel));
        assert_eq!(d.key(1, None, m), Some(Outcome::Cancel));
        assert_eq!(d.texts().0, "Restart the computer");
    }
}
