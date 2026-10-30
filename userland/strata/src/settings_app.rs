// SPDX-License-Identifier: MIT OR Apache-2.0

//! `strata-settings` (ADR 0039, rebuilt in ADR 0110): the computer's
//! settings in sections down a sidebar.
//!
//! - **Appearance:** the theme (Graphite, Light, Copper Noir or
//!   Sediment, ADR 0167) and the wallpaper,
//!   from the built-in designs, each shown small, or a picture of one's
//!   own (a path typed; ADR 0110's second addendum).
//! - **Accessibility:** high contrast, dimming unfocused windows,
//!   reduced motion.
//! - **Date and time:** the time zone.
//! - **Network:** automatic or a fixed address.
//! - **Users:** the people's accounts: add one, make it an administrator
//!   or not, change its password or full name, remove it; one's own
//!   picture (shown on the login and lock screens too).
//! - **Security:** the firewall (on or off, its open ports, opening and
//!   closing them through the broker), Slate mode, Linux compatibility (which can be turned
//!   off and on), the system image, disk encryption and the firewall.
//! - **Session:** locking after a while, and removing Strata.
//! - **About:** this computer.
//!
//! The person's own settings are in `~/.config/strata/settings`
//! ([`crate::settings`]); the rest are the system's, so changing them is
//! a broker action (`timezone=`, `network=`, `user=`, `compat=`,
//! `desktop=`, ADR 0054 and ADR 0110) that Strata's approval dialog asks
//! for.
//!
//! Keys: up and down choose a section; right, Tab or Enter go into it;
//! there up and down (and left and right among the wallpapers) choose,
//! Enter or space changes; Esc goes back. Fields edit as slate-ui's line
//! editor does (ADR 0101), with Strata's clipboard.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use slate_display::input::{
    KEY_BACKSPACE, KEY_DELETE, KEY_DOWN, KEY_END, KEY_ENTER, KEY_ESC, KEY_HOME, KEY_KPENTER, KEY_LEFT, KEY_RIGHT,
    KEY_SPACE, KEY_TAB, KEY_UP,
};
use slate_netconf::{Card, FieldErrors, Method};
use slate_rt::tz::Rule;
use slate_strata_client::mods::{ALT, CTRL, LOGO, SHIFT};
use slate_strata_client::{Connection, Event, Window};
use slate_ui::edit::{Clip, EditKey, LineEdit};
use slate_ui::graphite::Palette;
use slate_ui::icon::Icon;
use slate_ui::math::round;
use slate_ui::paint::Painter;
use slate_ui::text::GlyphCache;
use slate_ui::themes::Theme;
use slate_ui::ui::Area;
use slate_ui::wallpaper::Design;
use slate_ui::{Canvas, Color, Path};

use crate::fonts::Fonts;
use crate::settings::Settings;

/// The sections, down the sidebar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    Appearance,
    Accessibility,
    DateTime,
    Network,
    Bluetooth,
    Users,
    Security,
    Session,
    Displays,
    About,
}

pub const SECTIONS: [Section; 10] = [
    Section::Appearance,
    Section::Accessibility,
    Section::DateTime,
    Section::Network,
    Section::Bluetooth,
    Section::Users,
    Section::Security,
    Section::Session,
    Section::Displays,
    Section::About,
];

impl Section {
    pub fn title(self) -> &'static str {
        match self {
            Section::Appearance => "Appearance",
            Section::Accessibility => "Accessibility",
            Section::DateTime => "Date and time",
            Section::Network => "Network",
            Section::Bluetooth => "Bluetooth",
            Section::Users => "Users",
            Section::Security => "Security",
            Section::Session => "Session",
            Section::Displays => "Displays",
            Section::About => "About",
        }
    }

    fn blurb(self) -> &'static str {
        match self {
            Section::Appearance => "The theme of the desktop and its wallpaper.",
            Section::Accessibility => "Contrast, focus and motion.",
            Section::DateTime => "The computer's time zone, for everyone on it.",
            Section::Network => "How this computer gets its address.",
            Section::Bluetooth => "Devices nearby, and the ones paired with this computer.",
            Section::Users => "The people who can log in, and who administers.",
            Section::Security => "How Slate keeps programs apart, and the system intact.",
            Section::Session => "Locking the screen, and the desktop itself.",
            Section::Displays => "Where each display is, its resolution and refresh rate, and the scale.",
            Section::About => "This computer.",
        }
    }

    fn icon(self) -> Icon {
        match self {
            Section::Appearance => Icon::Picture,
            Section::Accessibility => Icon::Accessibility,
            Section::DateTime => Icon::Clock,
            Section::Network => Icon::Wifi,
            Section::Bluetooth => Icon::Bluetooth,
            Section::Users => Icon::People,
            Section::Security => Icon::Shield,
            Section::Session => Icon::Lock,
            Section::Displays => Icon::Display,
            Section::About => Icon::Info,
        }
    }
}

/// A person's account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub full: String,
    pub admin: bool,
    pub uid: u32,
}

impl Account {
    /// The full name, or the login when there is none.
    pub fn shown(&self) -> &str {
        if self.full.is_empty() { &self.name } else { &self.full }
    }
}

/// The people's accounts in passwd(5) and group(5) text: UIDs from 1000
/// (not nobody's) with a shell to log in with; administrators are in
/// wheel (ADR 0035).
pub fn accounts(passwd: &str, group: &str) -> Vec<Account> {
    let wheel: Vec<&str> = group
        .lines()
        .find_map(|l| l.strip_prefix("wheel:"))
        .and_then(|r| r.splitn(3, ':').nth(2))
        .map(|m| m.split(',').filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    passwd
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            let [name, _, uid, _, gecos, _, shell] = f[..] else { return None };
            let uid: u32 = uid.parse().ok()?;
            if uid < 1000 || uid == 65534 || shell.ends_with("nologin") || shell.ends_with("false") {
                return None;
            }
            let full = String::from(gecos.split(',').next().unwrap_or("").trim());
            Some(Account { name: name.into(), full, admin: wheel.contains(&name), uid })
        })
        .collect()
}

/// A login suggested from a full name: its first word, lower case,
/// letters and digits only ("Ada Lovelace" is ada).
pub fn suggest_login(full: &str) -> String {
    let first = full.split_whitespace().next().unwrap_or("");
    let s: String =
        first.chars().flat_map(char::to_lowercase).filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit()).collect();
    s.trim_start_matches(|c: char| c.is_ascii_digit()).chars().take(32).collect()
}

/// A login as useradd(8) takes it (shadow-utils' rule, as the broker
/// checks it).
pub fn valid_login(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-' | b'.'))
}

/// What Security shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Security {
    /// Linux compatibility mode; None where the kernel has no switch.
    pub compat: Option<bool>,
    /// Developer mode: root may change the image (ADR 0090).
    pub devmode: bool,
    /// The root is on an encrypted disk (ADR 0036).
    pub encrypted: bool,
    /// The firewall is on (ADR 0134; what slate-firewall last recorded,
    /// `None` if it never ran).
    pub firewall: Option<bool>,
    /// The ports /etc/slate/firewall opens: (TCP, port).
    pub ports: Vec<(bool, u16)>,
}

/// The ports a firewall configuration opens (`allow tcp 22` lines).
pub fn firewall_ports(text: &str) -> Vec<(bool, u16)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let words: Vec<&str> = line.split('#').next().unwrap_or("").split_whitespace().collect();
        if let ["allow", proto @ ("tcp" | "udp"), port] = words.as_slice()
            && let Ok(p) = port.parse::<u16>()
            && !out.contains(&(*proto == "tcp", p))
        {
            out.push((*proto == "tcp", p));
        }
    }
    out
}

/// A port typed to open: `8080` (TCP), `tcp 8080`, `udp 53` or `53/udp`.
pub fn typed_port(text: &str) -> Option<(bool, u16)> {
    let t = text.trim().to_ascii_lowercase();
    let (proto, port) = match t.split_once(['/', ' ']) {
        Some((a, b)) if a == "tcp" || a == "udp" => (a, b.trim()),
        Some((a, b)) if b.trim() == "tcp" || b.trim() == "udp" => (b.trim(), a),
        Some(_) => return None,
        None => ("tcp", t.as_str()),
    };
    port.parse::<u16>().ok().filter(|p| *p != 0).map(|p| (proto == "tcp", p))
}

/// What usually listens on a port, to say beside it.
fn port_use(tcp: bool, port: u16) -> &'static str {
    match (tcp, port) {
        (true, 22) => "SSH: logging in from other computers (sshd).",
        (true, 80) => "HTTP: a web server.",
        (true, 443) => "HTTPS: a web server.",
        (_, 53) => "DNS: a name server.",
        (true, 631) => "IPP: a printer shared from here.",
        (false, 5353) => "mDNS: finding devices on the local network.",
        _ => "Opened for a program that listens on it.",
    }
}

impl Security {
    pub fn read() -> Security {
        let flag = |p: &[u8]| slate_rt::fs::read_file(p).ok().map(|v| v.starts_with(b"1"));
        let mounts = slate_rt::fs::read_file(b"/proc/mounts").unwrap_or_default();
        let config = slate_rt::fs::read_file(b"/etc/slate/firewall").unwrap_or_default();
        Security {
            compat: flag(b"/proc/sys/slate/linux_compat"),
            devmode: flag(b"/proc/sys/slate/devmode").unwrap_or(false),
            encrypted: slate_rt::lossy(&mounts).lines().any(|l| l.starts_with("/dev/dm-") && l.contains(" / ")),
            firewall: slate_rt::fs::read_file(b"/run/slate-firewall").ok().map(|v| v.starts_with(b"on")),
            ports: firewall_ports(&slate_rt::lossy(&config)),
        }
    }

    /// The Security page's rows: Linux compatibility (when it can be
    /// changed), the firewall's switch, its open ports, and opening one.
    fn compat_rows(&self) -> usize {
        usize::from(self.compat.is_some())
    }

    fn rows(&self) -> usize {
        self.compat_rows() + 2 + self.ports.len()
    }
}

/// Where the keyboard is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    Sidebar,
    Content,
}

/// The add-account form's fields, in order.
pub const ADD_FIELDS: [&str; 4] = ["Full name", "User name", "Password", "Password again"];

/// A page within a section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Page {
    Main,
    /// The time zone list: the filter typed, the chosen match, the first
    /// match shown.
    Zones {
        query: LineEdit,
        selected: usize,
        first: usize,
    },
    /// The network page for one card (`*`: every card): whether a named
    /// card is set as every card is, a fixed address or not, the address,
    /// gateway and name server fields, which control has the keys (0: the
    /// choice, 1 to 3: the fields), and the fields' problems.
    Network {
        card: String,
        same: bool,
        fixed: bool,
        fields: Box<[LineEdit; 3]>,
        focus: usize,
        errors: FieldErrors,
    },
    /// One account: its rows are the administrator switch, the password
    /// and removing it (only the password for one's own).
    Account {
        name: String,
    },
    /// One display (ADR 0170): its rows are [`DISPLAY_ROWS`].
    Display {
        name: String,
    },
    /// A new password for an account, twice.
    Password {
        name: String,
        fields: Box<[LineEdit; 2]>,
        focus: usize,
        error: Option<String>,
    },
    /// A picture to choose (for [`Entry::Wallpaper`] or [`Entry::Face`])
    /// among [`View::pictures`]: the row chosen and the first shown.
    Pick {
        what: Entry,
        selected: usize,
        first: usize,
    },
    /// A path or a name typed: what for, the field, and its problem.
    Entry {
        what: Entry,
        field: LineEdit,
        error: Option<String>,
    },
    /// A new account: the fields of [`ADD_FIELDS`] (0 to 3), the
    /// administrator switch (4) and the button (5); whether the user name
    /// was typed (else it follows the full name).
    Add {
        fields: Box<[LineEdit; 4]>,
        admin: bool,
        focus: usize,
        error: Option<(usize, String)>,
        typed_login: bool,
    },
}

/// What a [`Page::Entry`] is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    /// The path of a picture for the wallpaper.
    Wallpaper,
    /// An account's full name.
    Name(String),
    /// The path of a picture for one's own account (empty: none).
    Face(String),
    /// A port to open in the firewall.
    Port,
}

/// The account page's rows, by what they do.
const ROW_ADMIN: usize = 0;
const ROW_PASSWORD: usize = 1;
const ROW_REMOVE: usize = 2;
const ROW_NAME: usize = 3;
const ROW_FACE: usize = 4;
const ROW_EXPIRE: usize = 5;

/// What a key or click asks the program to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    None,
    Redraw,
    /// The person's settings changed: write them.
    Save,
    /// Ask the broker to set this time zone.
    SetZone(String),
    /// Ask the broker for these network settings (ADR 0054).
    SetNetwork(Card),
    /// Ask the broker to set this card as every card is (its section
    /// taken away).
    NetworkDefault(String),
    /// Put this text on Strata's clipboard.
    Copy(String),
    /// Ask Strata for its clipboard (then [`View::paste`]).
    Paste,
    /// Ask the broker to remove Strata (`desktop=remove`).
    RemoveDesktop,
    /// Ask the broker for full graphics (`graphics=full`, AMD's firmware)
    /// or SlateOS only (`graphics=slate`), ADR 0173.
    Graphics(bool),
    /// Ask the broker for an account change (`user=WORDS`), with the
    /// account's new password when it takes one.
    User(String, String),
    /// Ask the broker to turn Linux compatibility on or off.
    Compat(bool),
    /// Ask the broker to change the firewall (`firewall=WORDS`).
    Firewall(String),
    /// Ask the Bluetooth daemon (ADR 0113): its request's words.
    Bluetooth(String),
    /// Make the picture at this path the wallpaper.
    Wallpaper(String),
    /// Make the picture at this path one's own account's (empty: none).
    Face(String),
    /// Find the pictures to choose from, then [`View::open_pick`].
    Pictures(Entry),
    /// Write this arrangement of the displays (the displays file's text,
    /// ADR 0170): Strata applies it.
    Displays(String),
}

/// A display's page: its resolution, refresh rate, place beside the
/// primary, whether it is primary, whether it is on.
pub const DISPLAY_ROWS: [&str; 5] = ["Resolution", "Refresh rate", "Position", "Primary display", "On"];

/// Full graphics on this machine (ADR 0173): whether AMD's firmware is
/// installed (it takes effect at the next start), whether the system's
/// repository has it, whether this session started with it, and whether
/// this is the live system (which has no next start: the installer asks).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Graphics {
    pub installed: bool,
    pub available: bool,
    pub running: bool,
    pub live: bool,
}

impl Graphics {
    /// What the Graphics row says.
    pub fn words(&self, confirming: bool) -> &'static str {
        if self.live {
            return "chosen at install";
        }
        match (self.installed, self.running, confirming) {
            (true, _, true) => "enter to turn off",
            (true, true, _) => "full graphics",
            (true, false, _) => "full at next start",
            (false, true, _) => "SlateOS at next start",
            (false, false, _) => "SlateOS only",
        }
    }

    /// This machine's, if it has an AMD card Slate's driver has.
    pub fn now() -> Option<Graphics> {
        use slate_display::graphics as g;
        (g::amd_cards() > 0).then(|| {
            let installed = g::full_graphics();
            // The driver lit a card: a DRM card under one of its functions.
            let running = slate_sysinfo::graphics().iter().any(|(_, c)| c.contains("AMD's firmware"));
            let live = slate_rt::fs::exists(crate::session::LIVE.as_bytes());
            Graphics { installed, available: g::available(), running, live }
        })
    }
}

/// The app's state.
#[derive(Clone, Debug)]
pub struct View {
    pub settings: Settings,
    /// The displays Strata found, as Settings › Displays shows and edits
    /// them (ADR 0170).
    pub displays: crate::displays::Now,
    /// The system's zone name.
    pub zone: String,
    /// The settings for every card (`[*]`), if the file has them.
    pub network: Option<Card>,
    /// The cards with settings of their own (sections other than `[*]`).
    pub named: Vec<Card>,
    /// The computer's network cards (but the loopback).
    pub cards: Vec<String>,
    /// Pictures found to choose from (paths), for [`Page::Pick`].
    pub pictures: Vec<String>,
    /// One's home folder, shown as `~` in the chooser.
    pub home: String,
    pub accounts: Vec<Account>,
    /// Who runs Settings (their account can't remove itself).
    pub me: String,
    pub security: Security,
    /// About's rows.
    pub about: Vec<(String, String)>,
    /// Full graphics (ADR 0173), on a machine with an AMD card Slate's
    /// driver has.
    pub graphics: Option<Graphics>,
    pub section: usize,
    pub focus: Focus,
    /// The chosen row in the section (or page).
    pub row: usize,
    pub page: Page,
    /// Keys have been used: show the focus outline (WM_STYLE §10).
    pub focus_visible: bool,
    pub status: String,
    /// The status says something went wrong (in clay).
    pub status_bad: bool,
    /// Enter was pressed once on a removal: the next one does it.
    pub removing: bool,
    /// What slate-btd says (None: it isn't running; ADR 0113).
    pub bluetooth: Option<slate_bluetooth::proto::Snapshot>,
    /// The wallpaper picture of one's own, if there is one, to show.
    pub picture: Option<slate_image::Image>,
    /// The accounts' pictures, by login.
    pub faces: Vec<(String, slate_image::Image)>,
}

/// The zones whose names hold every word of `query`, ignoring case, with
/// `_` read as a space ("new york" finds America/New_York).
pub fn matches<'a>(names: &'a [String], query: &str) -> Vec<&'a str> {
    let q = query.to_ascii_lowercase();
    let words: Vec<&str> = q.split_whitespace().collect();
    names
        .iter()
        .filter(|n| {
            let n = n.to_ascii_lowercase().replace('_', " ");
            words.iter().all(|w| n.contains(w))
        })
        .map(String::as_str)
        .collect()
}

/// The appearance rows: the themes, then the wallpapers.
const STYLES: usize = Theme::ALL.len();
/// Wallpapers in a row of the grid.
const WALL_COLS: usize = 4;

/// A field's key: the line editor's, or None for keys it doesn't take.
fn edit_key(field: &mut LineEdit, code: u16, ch: Option<char>, mods: u8) -> Option<slate_ui::edit::Outcome> {
    let shortcut = mods & (CTRL | ALT | LOGO) != 0;
    let (shift, ctrl) = (mods & SHIFT != 0, mods & CTRL != 0);
    let edit = match (code, ch) {
        (KEY_LEFT, _) => Some(EditKey::Left),
        (KEY_RIGHT, _) => Some(EditKey::Right),
        (KEY_HOME, _) => Some(EditKey::Home),
        (KEY_END, _) => Some(EditKey::End),
        (KEY_BACKSPACE, _) => Some(EditKey::Backspace),
        (KEY_DELETE, _) => Some(EditKey::Delete),
        (_, Some('a')) if ctrl => Some(EditKey::SelectAll),
        (_, Some('c')) if ctrl => Some(EditKey::Copy),
        (_, Some('x')) if ctrl => Some(EditKey::Cut),
        (_, Some('v')) if ctrl => Some(EditKey::Paste),
        _ => None,
    };
    match (edit, ch.filter(|c| !shortcut && !c.is_control())) {
        (Some(k), _) => Some(field.key(k, shift, ctrl)),
        (None, Some(c)) => {
            let changed = field.insert(c.encode_utf8(&mut [0u8; 4]));
            Some(slate_ui::edit::Outcome { changed, moved: changed, clip: Clip::None })
        }
        (None, None) => None,
    }
}

/// What a field's edit means for the program.
fn clip_effect(out: &slate_ui::edit::Outcome) -> Effect {
    match &out.clip {
        Clip::Copy(t) => Effect::Copy(t.clone()),
        Clip::Paste => Effect::Paste,
        Clip::None if out.moved || out.changed => Effect::Redraw,
        Clip::None => Effect::None,
    }
}

impl View {
    pub fn new(settings: Settings, zone: &str) -> View {
        View {
            settings,
            displays: crate::displays::Now::default(),
            zone: String::from(zone),
            network: None,
            named: Vec::new(),
            cards: Vec::new(),
            pictures: Vec::new(),
            home: String::new(),
            accounts: Vec::new(),
            me: String::new(),
            security: Security::default(),
            about: Vec::new(),
            graphics: None,
            section: 0,
            focus: Focus::Sidebar,
            row: 0,
            page: Page::Main,
            focus_visible: false,
            status: String::new(),
            status_bad: false,
            removing: false,
            bluetooth: None,
            picture: None,
            faces: Vec::new(),
        }
    }

    /// `login`'s picture, if it has one.
    pub fn face(&self, login: &str) -> Option<&slate_image::Image> {
        self.faces.iter().find(|(n, _)| n == login).map(|(_, i)| i)
    }

    /// The Bluetooth page's devices, in its order: the paired ones, then
    /// the others nearby.
    pub fn bt_devices(&self) -> Vec<slate_bluetooth::proto::Seen> {
        let Some(b) = &self.bluetooth else { return Vec::new() };
        let mut v: Vec<_> = b.devices.iter().filter(|d| d.paired || d.nearby).cloned().collect();
        v.sort_by_key(|d| (!d.paired, d.name.to_lowercase()));
        v
    }

    /// Whether the Bluetooth page asks a yes or no (pairing).
    fn bt_question(&self) -> Option<slate_hci::BdAddr> {
        use slate_bluetooth::host::Prompt;
        match self.bluetooth.as_ref()?.prompt? {
            Prompt::Confirm(a, _) | Prompt::Pair(a) => Some(a),
            Prompt::Passkey(..) => None,
        }
    }

    pub fn current(&self) -> Section {
        SECTIONS[self.section]
    }

    /// How many rows the section's main page has.
    fn rows(&self) -> usize {
        match self.current() {
            // The designs, then a picture of one's own.
            Section::Appearance => STYLES + Design::ALL.len() + 1,
            Section::Accessibility => 3,
            Section::DateTime => 1,
            // Every card, then each card.
            Section::Network => 1 + self.cards.len(),
            Section::Bluetooth => match &self.bluetooth {
                Some(b) if b.on() => 1 + self.bt_devices().len(),
                Some(b) if b.state != "none" => 1,
                _ => 0,
            },
            Section::Users => self.accounts.len() + 1,
            Section::Security => self.security.rows(),
            Section::Session => 2,
            // Each display, then the scale, then full graphics where
            // there is an AMD card.
            Section::Displays => self.displays.displays.len() + 1 + usize::from(self.graphics.is_some()),
            Section::About => 0,
        }
    }

    /// The account page's rows: administrator, password, remove (one's
    /// own: the password only).
    fn account_rows(&self, name: &str) -> &'static [usize] {
        if name == self.me {
            &[ROW_PASSWORD, ROW_NAME, ROW_FACE]
        } else {
            &[ROW_ADMIN, ROW_PASSWORD, ROW_EXPIRE, ROW_NAME, ROW_REMOVE]
        }
    }

    /// Open account `name`'s page, on its first row.
    fn open_account(&mut self, name: &str, row: Option<usize>) {
        let first = self.account_rows(name)[0];
        self.go(Page::Account { name: String::from(name) });
        self.row = row.unwrap_or(first);
    }

    /// The picture chooser for `what`, over [`View::pictures`] (found by
    /// the program just before).
    pub fn open_pick(&mut self, what: Entry) {
        self.go(Page::Pick { what, selected: 0, first: 0 });
        self.focus = Focus::Content;
    }

    /// The path typed in the old way: the path page.
    fn type_path(&mut self, what: Entry) {
        let mut field = LineEdit::new("~/Pictures/").with_max(1024);
        field.place(usize::MAX, false);
        self.go(Page::Entry { what, field, error: None });
    }

    /// Enter on the chooser's row `row`.
    fn pick(&mut self, what: Entry, row: usize) -> Effect {
        let none = usize::from(matches!(what, Entry::Face(_)));
        if none == 1 && row == 0 {
            return Effect::Face(String::new());
        }
        match self.pictures.get(row - none).cloned() {
            Some(path) if what == Entry::Wallpaper => Effect::Wallpaper(path),
            Some(path) => Effect::Face(path),
            None => {
                self.type_path(what);
                Effect::Redraw
            }
        }
    }

    /// Say something on the status line.
    pub fn say(&mut self, text: &str, bad: bool) {
        self.status = String::from(text);
        self.status_bad = bad;
    }

    fn go(&mut self, page: Page) {
        self.page = page;
        self.row = 0;
        self.removing = false;
        self.status.clear();
    }

    /// Choose section `i` from the sidebar.
    pub fn open_section(&mut self, i: usize) {
        if i < SECTIONS.len() {
            self.section = i;
            self.focus = Focus::Sidebar;
            self.go(Page::Main);
        }
    }

    /// Enter or space on the main page's row `row`.
    fn activate(&mut self, row: usize) -> Effect {
        let section = self.current();
        // A removal asked about waits for its second Enter (moving away
        // forgets it).
        let port_row =
            section == Section::Security && row > self.security.compat_rows() && row < self.security.rows() - 1;
        if !(section == Section::Session && row == 1) && !(section == Section::Bluetooth && row > 0) && !port_row {
            self.removing = false;
        }
        let s = &mut self.settings;
        match section {
            // A theme brings its own wallpaper (ADR 0167); a picture of
            // one's own stays.
            Section::Appearance if row < STYLES => {
                s.theme = Theme::ALL[row];
                s.wallpaper = s.theme.wallpaper();
            }
            Section::Appearance if row == STYLES + Design::ALL.len() => {
                return Effect::Pictures(Entry::Wallpaper);
            }
            Section::Appearance => {
                s.wallpaper = Design::ALL[row - STYLES];
                s.picture = false;
            }
            Section::Accessibility => match row {
                0 => s.high_contrast = !s.high_contrast,
                1 => s.dim = !s.dim,
                _ => s.reduced_motion = !s.reduced_motion,
            },
            Section::DateTime => {
                self.go(Page::Zones { query: LineEdit::new("").with_max(64), selected: 0, first: 0 });
                return Effect::Redraw;
            }
            Section::Network => {
                let card = if row == 0 { String::from("*") } else { self.cards[row - 1].clone() };
                self.open_network(&card);
                return Effect::Redraw;
            }
            Section::Bluetooth if row == 0 => {
                let on = self.bluetooth.as_ref().is_some_and(|b| b.on());
                return Effect::Bluetooth(String::from(if on { "power off" } else { "power on" }));
            }
            Section::Bluetooth => {
                let Some(d) = self.bt_devices().get(row - 1).cloned() else { return Effect::None };
                if !d.paired {
                    return Effect::Bluetooth(alloc::format!("pair {}", d.addr));
                }
                if self.removing {
                    self.removing = false;
                    return Effect::Bluetooth(alloc::format!("remove {}", d.addr));
                }
                self.removing = true;
                self.say(&alloc::format!("Press Enter again to forget {}.", d.name), true);
                return Effect::Redraw;
            }
            Section::Displays => {
                if let Some(d) = self.displays.displays.get(row) {
                    let name = d.name.clone();
                    self.go(Page::Display { name });
                    self.focus = Focus::Content;
                    return Effect::Redraw;
                }
                if row > self.displays.displays.len() {
                    return match self.graphics {
                        // The live system forgets everything at shutdown.
                        Some(g) if g.live => {
                            self.say("Full graphics is chosen when SlateOS is installed: the installer asks.", false);
                            Effect::Redraw
                        }
                        Some(g) if !g.installed && !g.available => {
                            self.say("This system's repository doesn't have AMD's firmware.", true);
                            Effect::Redraw
                        }
                        Some(g) if g.installed && !self.removing => {
                            self.removing = true;
                            self.say("Press Enter again to stop loading AMD's firmware.", true);
                            Effect::Redraw
                        }
                        Some(g) => {
                            self.removing = false;
                            Effect::Graphics(!g.installed)
                        }
                        None => Effect::None,
                    };
                }
                let auto = self.auto_scale();
                self.displays.next_scale(auto);
                return Effect::Displays(self.displays.arrangement().render());
            }
            Section::Users => {
                match self.accounts.get(row) {
                    Some(a) => {
                        let name = a.name.clone();
                        self.open_account(&name, None);
                    }
                    None => self.go(Page::Add {
                        fields: Box::new(core::array::from_fn(|i| {
                            let f = LineEdit::new("").with_max(if i == 0 { 64 } else { 32 });
                            if i >= 2 { f.with_max(128).secret() } else { f }
                        })),
                        admin: false,
                        focus: 0,
                        error: None,
                        typed_login: false,
                    }),
                }
                self.focus = Focus::Content;
                return Effect::Redraw;
            }
            Section::Security => {
                let sec = &self.security;
                let first = sec.compat_rows();
                if let (Some(on), 0) = (sec.compat, row) {
                    return Effect::Compat(!on);
                }
                if row == first {
                    let on = sec.firewall.unwrap_or(true);
                    return Effect::Firewall(String::from(if on { "off" } else { "on" }));
                }
                if row == sec.rows() - 1 {
                    let mut field = LineEdit::new("").with_max(16);
                    field.place(usize::MAX, false);
                    self.go(Page::Entry { what: Entry::Port, field, error: None });
                    self.focus = Focus::Content;
                    return Effect::Redraw;
                }
                // A port: closed on a second Enter (it may be how someone
                // reaches this computer).
                let (tcp, port) = sec.ports[row - first - 1];
                if self.removing {
                    self.removing = false;
                    return Effect::Firewall(alloc::format!("deny {} {port}", if tcp { "tcp" } else { "udp" }));
                }
                self.removing = true;
                self.say(
                    &alloc::format!("Press Enter again to close {} port {port}.", if tcp { "TCP" } else { "UDP" }),
                    true,
                );
                return Effect::Redraw;
            }
            Section::Session if row == 0 => {
                let at = crate::settings::LOCK_CHOICES.iter().position(|&c| c == s.lock).unwrap_or(0);
                s.lock = crate::settings::LOCK_CHOICES[(at + 1) % crate::settings::LOCK_CHOICES.len()];
            }
            Section::Session => {
                if self.removing {
                    self.removing = false;
                    return Effect::RemoveDesktop;
                }
                self.removing = true;
                self.say("Press Enter again to remove Strata.", true);
                return Effect::Redraw;
            }
            Section::About => return Effect::None,
        }
        Effect::Save
    }

    /// The settings card `name` has (`*`: every card's); `None` for a
    /// named card set as every card is.
    fn card_settings(&self, name: &str) -> Option<&Card> {
        if name == "*" { self.network.as_ref() } else { self.named.iter().find(|c| c.name == name) }
    }

    /// The network page for card `card`, filled in from its settings (a
    /// card set as every card is starts from every card's).
    fn open_network(&mut self, card: &str) {
        let same = card != "*" && self.card_settings(card).is_none();
        let own = self.card_settings(card).or(self.network.as_ref());
        let (fixed, fields) = match own.map(|c| (&c.method, &c.dns)) {
            Some((Method::Static { addr, prefix_len, gateway }, dns)) => {
                let dns: Vec<String> = dns.iter().map(|d| alloc::format!("{d}")).collect();
                let gateway = gateway.map(|g| alloc::format!("{g}")).unwrap_or_default();
                (true, [alloc::format!("{addr}/{prefix_len}"), gateway, dns.join(" ")])
            }
            _ => (false, Default::default()),
        };
        let fields = Box::new(fields.map(|f: String| LineEdit::new(&f).with_max(64)));
        self.go(Page::Network {
            card: String::from(card),
            same,
            fixed: fixed && !same,
            fields,
            focus: 0,
            errors: FieldErrors::default(),
        });
    }

    /// The field with the keys, on a page that has fields.
    fn focused_field(&mut self) -> Option<&mut LineEdit> {
        match &mut self.page {
            Page::Network { fields, focus, .. } if *focus > 0 => Some(&mut fields[*focus - 1]),
            Page::Password { fields, focus, .. } if *focus < 2 => Some(&mut fields[*focus]),
            Page::Add { fields, focus, .. } if *focus < 4 => Some(&mut fields[*focus]),
            Page::Entry { field, .. } => Some(field),
            _ => None,
        }
    }

    /// Text from Strata's clipboard, for the focused field.
    pub fn paste(&mut self, text: &str) -> Effect {
        let Some(field) = self.focused_field() else { return Effect::None };
        if !field.insert(text) {
            return Effect::None;
        }
        self.edited();
        Effect::Redraw
    }

    /// A field changed: its problem goes, and a new account's user name
    /// follows its full name until typed.
    fn edited(&mut self) {
        match &mut self.page {
            Page::Network { errors, focus, .. } => clear_error(errors, *focus),
            Page::Password { error, .. } | Page::Entry { error, .. } => *error = None,
            Page::Add { fields, focus, error, typed_login, .. } => {
                if error.as_ref().is_some_and(|e| e.0 == *focus) {
                    *error = None;
                }
                match *focus {
                    0 if !*typed_login => {
                        let s = suggest_login(&fields[0].text());
                        fields[1].set_text(&s);
                    }
                    1 => *typed_login = true,
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// Back from a page (or from the content to the sidebar).
    fn back(&mut self) {
        match &self.page {
            Page::Main => self.focus = Focus::Sidebar,
            Page::Password { name, .. } => {
                let name = name.clone();
                self.open_account(&name, Some(ROW_PASSWORD));
            }
            Page::Entry { what: Entry::Name(name), .. } => {
                let name = name.clone();
                self.open_account(&name, Some(ROW_NAME));
            }
            Page::Entry { what: Entry::Face(name), .. } => {
                let name = name.clone();
                self.open_account(&name, Some(ROW_FACE));
            }
            Page::Entry { what: Entry::Wallpaper, .. } | Page::Pick { what: Entry::Wallpaper, .. } => {
                self.go(Page::Main);
                self.row = STYLES + Design::ALL.len();
            }
            Page::Pick { what: Entry::Face(name), .. } => {
                let name = name.clone();
                self.open_account(&name, Some(ROW_FACE));
            }
            Page::Entry { what: Entry::Port, .. } => {
                self.go(Page::Main);
                self.row = self.security.rows() - 1;
            }
            _ => {
                let row = match (&self.page, self.current()) {
                    (Page::Account { name }, _) => self.accounts.iter().position(|a| a.name == *name).unwrap_or(0),
                    (Page::Display { name }, _) => {
                        self.displays.displays.iter().position(|d| d.name == *name).unwrap_or(0)
                    }
                    (Page::Add { .. }, _) => self.accounts.len(),
                    _ => 0,
                };
                self.go(Page::Main);
                self.row = row;
            }
        }
        self.removing = false;
    }

    /// Check the add-account form; the change to ask for, or where the
    /// problem is.
    fn add_account(&mut self) -> Effect {
        let Page::Add { fields, admin, focus, error, .. } = &mut self.page else { return Effect::None };
        let [full, login, pw, again] = [0, 1, 2, 3].map(|i| fields[i].text());
        let problem = if full.contains([':', ',']) {
            Some((0, "A name can't hold : or ,"))
        } else if !valid_login(&login) {
            Some((1, "Lower-case letters, digits, - and _, starting with a letter"))
        } else if self.accounts.iter().any(|a| a.name == login) || login == "root" {
            Some((1, "There is an account with that name already"))
        } else if pw.is_empty() {
            Some((2, "Choose a password"))
        } else if pw != again {
            Some((3, "The two passwords are not the same"))
        } else {
            None
        };
        if let Some((at, text)) = problem {
            *error = Some((at, String::from(text)));
            *focus = at;
            return Effect::Redraw;
        }
        let kind = if *admin { "admin" } else { "standard" };
        Effect::User(alloc::format!("add {login} {kind} {}", full.trim()), pw)
    }

    /// A key (evdev code, the character it types, the modifier bits of
    /// the protocol); `names` are the zones.
    pub fn key(&mut self, code: u16, ch: Option<char>, mods: u8, names: &[String]) -> Effect {
        let shortcut = mods & (CTRL | ALT | LOGO) != 0;
        let shift = mods & SHIFT != 0;
        self.focus_visible = true;
        // The sidebar.
        if self.focus == Focus::Sidebar {
            match code {
                KEY_UP if self.section > 0 => self.open_section(self.section - 1),
                KEY_DOWN if self.section + 1 < SECTIONS.len() => self.open_section(self.section + 1),
                KEY_RIGHT | KEY_TAB | KEY_ENTER | KEY_KPENTER | KEY_SPACE if self.rows() > 0 => {
                    self.focus = Focus::Content;
                    self.row = 0;
                }
                KEY_UP | KEY_DOWN => {}
                _ => return Effect::None,
            }
            return Effect::Redraw;
        }
        // A pairing's question: Enter says yes, Esc no.
        if self.current() == Section::Bluetooth
            && self.page == Page::Main
            && let Some(a) = self.bt_question()
            && matches!(code, KEY_ENTER | KEY_KPENTER | KEY_ESC)
        {
            let yes = code != KEY_ESC;
            return Effect::Bluetooth(alloc::format!("confirm {a} {}", if yes { "yes" } else { "no" }));
        }
        if code == KEY_ESC || (code == KEY_TAB && shift && self.page == Page::Main) {
            self.back();
            return Effect::Redraw;
        }
        let rows = self.rows();
        match &mut self.page {
            Page::Main => match code {
                KEY_SPACE | KEY_ENTER | KEY_KPENTER => return self.activate(self.row),
                // Bluetooth: Delete forgets a paired device (asking
                // first), r looks again.
                KEY_DELETE if self.current() == Section::Bluetooth && self.row > 0 => {
                    let paired = self.bt_devices().get(self.row - 1).is_some_and(|d| d.paired);
                    return if paired { self.activate(self.row) } else { Effect::None };
                }
                _ if self.current() == Section::Bluetooth && ch == Some('r') && !shortcut => {
                    return Effect::Bluetooth(String::from("discover"));
                }
                _ if self.current() == Section::Appearance => {
                    let r = self.row;
                    self.row = match code {
                        KEY_LEFT if r == 0 => {
                            self.focus = Focus::Sidebar;
                            r
                        }
                        KEY_LEFT => r - 1,
                        KEY_RIGHT | KEY_TAB => (r + 1).min(rows - 1),
                        KEY_DOWN if r < STYLES => STYLES + r,
                        KEY_DOWN => (r + WALL_COLS).min(rows - 1),
                        KEY_UP if r < STYLES => r,
                        KEY_UP if r < STYLES + WALL_COLS => (r - STYLES).min(STYLES - 1),
                        KEY_UP => r - WALL_COLS,
                        _ => return Effect::None,
                    };
                }
                KEY_UP => {
                    self.row = self.row.saturating_sub(1);
                    self.removing = false;
                }
                KEY_DOWN | KEY_TAB => {
                    self.row = (self.row + 1).min(rows.saturating_sub(1));
                    self.removing = false;
                }
                KEY_LEFT => self.focus = Focus::Sidebar,
                _ => return Effect::None,
            },
            Page::Pick { what, selected, first } => {
                let rows = self.pictures.len() + 1 + usize::from(matches!(what, Entry::Face(_)));
                match code {
                    KEY_UP => *selected = selected.saturating_sub(1),
                    KEY_DOWN => *selected = (*selected + 1).min(rows - 1),
                    KEY_HOME => *selected = 0,
                    KEY_END => *selected = rows - 1,
                    KEY_ENTER | KEY_KPENTER | KEY_SPACE => {
                        let (what, row) = (what.clone(), *selected);
                        return self.pick(what, row);
                    }
                    _ => return Effect::None,
                }
                // Keep the chosen row in view (the page shows PICK_SHOWN).
                if *selected < *first {
                    *first = *selected;
                } else if *selected >= *first + PICK_SHOWN {
                    *first = *selected + 1 - PICK_SHOWN;
                }
            }
            Page::Zones { query, selected, first } => {
                let found = matches(names, &query.text()).len();
                match code {
                    KEY_UP => *selected = selected.saturating_sub(1),
                    KEY_DOWN => *selected = (*selected + 1).min(found.saturating_sub(1)),
                    KEY_ENTER | KEY_KPENTER => {
                        let Some(z) = matches(names, &query.text()).get(*selected).map(|z| String::from(*z)) else {
                            return Effect::None;
                        };
                        self.go(Page::Main);
                        return Effect::SetZone(z);
                    }
                    // The filter is a field (ADR 0101): the caret moves.
                    _ => {
                        let Some(out) = edit_key(query, code, ch, mods) else { return Effect::None };
                        if out.changed {
                            (*selected, *first) = (0, 0);
                        }
                        return clip_effect(&out);
                    }
                }
            }
            Page::Network { card: name, same, fixed, fields, focus, errors } => {
                let last = if *fixed { 3 } else { 0 };
                // The choices: as every card (a named card's), automatic,
                // fixed.
                let first = usize::from(name != "*");
                let at = if *same { 0 } else { first + usize::from(*fixed) };
                let mut choose = |c: usize| {
                    *same = c < first;
                    *fixed = c == first + 1;
                };
                match code {
                    KEY_TAB | KEY_DOWN => *focus = (*focus + 1).min(last),
                    KEY_UP => *focus = focus.saturating_sub(1),
                    KEY_LEFT if *focus == 0 => choose(at.saturating_sub(1)),
                    KEY_RIGHT if *focus == 0 => choose((at + 1).min(first + 1)),
                    KEY_SPACE if *focus == 0 => choose((at + 1) % (first + 2)),
                    KEY_ENTER | KEY_KPENTER if *same => {
                        let card = name.clone();
                        self.go(Page::Main);
                        return Effect::NetworkDefault(card);
                    }
                    KEY_ENTER | KEY_KPENTER => {
                        let card = if *fixed {
                            let [a, g, d] = [fields[0].text(), fields[1].text(), fields[2].text()];
                            match slate_netconf::fixed(name, &a, &g, &d) {
                                Ok(c) => c,
                                Err(e) => {
                                    // The first field at fault gets the keys.
                                    *focus = if e.address.is_some() {
                                        1
                                    } else if e.gateway.is_some() {
                                        2
                                    } else {
                                        3
                                    };
                                    *errors = e;
                                    return Effect::Redraw;
                                }
                            }
                        } else {
                            Card { name: name.clone(), method: Method::Dhcp, six: Default::default(), dns: Vec::new() }
                        };
                        self.go(Page::Main);
                        return Effect::SetNetwork(card);
                    }
                    _ => return self.field_key(code, ch, mods),
                }
            }
            Page::Account { name } => {
                let name = name.clone();
                let allowed = self.account_rows(&name);
                let at = allowed.iter().position(|&r| r == self.row).unwrap_or(0);
                match code {
                    KEY_UP => {
                        self.row = allowed[at.saturating_sub(1)];
                        self.removing = false;
                    }
                    KEY_DOWN | KEY_TAB => {
                        self.row = allowed[(at + 1).min(allowed.len() - 1)];
                        self.removing = false;
                    }
                    KEY_SPACE | KEY_ENTER | KEY_KPENTER => return self.account_action(&name),
                    _ => return Effect::None,
                }
            }
            Page::Display { name } => {
                let name = name.clone();
                match code {
                    KEY_UP => self.row = self.row.saturating_sub(1),
                    KEY_DOWN | KEY_TAB => self.row = (self.row + 1).min(DISPLAY_ROWS.len() - 1),
                    KEY_SPACE | KEY_ENTER | KEY_KPENTER => return self.display_action(&name),
                    _ => return Effect::None,
                }
            }
            Page::Password { name, fields, focus, error } => match code {
                KEY_TAB | KEY_DOWN => *focus = (*focus + 1).min(1),
                KEY_UP => *focus = focus.saturating_sub(1),
                KEY_ENTER | KEY_KPENTER if *focus == 0 => *focus = 1,
                KEY_ENTER | KEY_KPENTER => {
                    let (pw, again) = (fields[0].text(), fields[1].text());
                    if pw.is_empty() {
                        (*error, *focus) = (Some("Choose a password".into()), 0);
                    } else if pw != again {
                        *error = Some("The two passwords are not the same".into());
                    } else {
                        return Effect::User(alloc::format!("password {name}"), pw);
                    }
                }
                _ => return self.field_key(code, ch, mods),
            },
            Page::Entry { what, field, error } => match code {
                KEY_ENTER | KEY_KPENTER => {
                    let text = field.text();
                    let path = |t: &str| match t.trim().strip_prefix('~') {
                        Some(r) => {
                            let home = slate_rt::env::var(b"HOME").map(|h| String::from(slate_rt::lossy(&h)));
                            alloc::format!("{}{r}", home.unwrap_or_default())
                        }
                        None => String::from(t.trim()),
                    };
                    return match what {
                        Entry::Wallpaper if text.trim().is_empty() || text.trim().ends_with('/') => {
                            *error = Some(String::from("Type the path of a picture."));
                            Effect::Redraw
                        }
                        Entry::Wallpaper => Effect::Wallpaper(path(&text)),
                        Entry::Face(_) if text.trim().is_empty() => Effect::Face(String::new()),
                        Entry::Face(_) if text.trim().ends_with('/') => {
                            *error = Some(String::from("Type the path of a picture, or nothing for none."));
                            Effect::Redraw
                        }
                        Entry::Face(_) => Effect::Face(path(&text)),
                        Entry::Name(_) if text.contains([':', ',']) => {
                            *error = Some(String::from("A name can't hold : or ,"));
                            Effect::Redraw
                        }
                        Entry::Name(login) => {
                            Effect::User(alloc::format!("name {login} {}", text.trim()), String::new())
                        }
                        Entry::Port => match typed_port(&text) {
                            Some((tcp, port)) => {
                                Effect::Firewall(alloc::format!("allow {} {port}", if tcp { "tcp" } else { "udp" }))
                            }
                            None => {
                                *error = Some(String::from("Type a port from 1 to 65535, and tcp or udp if not TCP."));
                                Effect::Redraw
                            }
                        },
                    };
                }
                _ => return self.field_key(code, ch, mods),
            },
            Page::Add { admin, focus, .. } => match code {
                KEY_TAB | KEY_DOWN => *focus = (*focus + 1).min(5),
                KEY_UP => *focus = focus.saturating_sub(1),
                KEY_SPACE if *focus == 4 => *admin = !*admin,
                KEY_ENTER | KEY_KPENTER => match *focus {
                    4 => *admin = !*admin,
                    5 => return self.add_account(),
                    _ => *focus += 1,
                },
                _ => return self.field_key(code, ch, mods),
            },
        }
        Effect::Redraw
    }

    /// A key for the focused field.
    fn field_key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        let Some(field) = self.focused_field() else { return Effect::None };
        let Some(out) = edit_key(field, code, ch, mods) else { return Effect::None };
        if out.changed {
            self.edited();
        }
        clip_effect(&out)
    }

    /// Enter on an account page's row.
    fn account_action(&mut self, name: &str) -> Effect {
        let acc = self.accounts.iter().find(|a| a.name == name);
        let admin = acc.is_some_and(|a| a.admin);
        let full = acc.map(|a| a.full.clone()).unwrap_or_default();
        match self.row {
            ROW_ADMIN => {
                Effect::User(alloc::format!("{} {name}", if admin { "standard" } else { "admin" }), String::new())
            }
            ROW_NAME => {
                let mut field = LineEdit::new(&full).with_max(64);
                field.place(usize::MAX, false);
                self.go(Page::Entry { what: Entry::Name(String::from(name)), field, error: None });
                Effect::Redraw
            }
            ROW_FACE => Effect::Pictures(Entry::Face(String::from(name))),
            ROW_EXPIRE => Effect::User(alloc::format!("expire {name}"), String::new()),
            ROW_PASSWORD => {
                let fields = Box::new(core::array::from_fn(|_| LineEdit::new("").with_max(128).secret()));
                self.go(Page::Password { name: String::from(name), fields, focus: 0, error: None });
                Effect::Redraw
            }
            _ if self.removing => {
                self.removing = false;
                Effect::User(alloc::format!("remove {name}"), String::new())
            }
            _ => {
                self.removing = true;
                self.say("Press Enter again to remove the account and its files.", true);
                Effect::Redraw
            }
        }
    }

    /// The scale Strata would choose itself, by the primary display's size.
    fn auto_scale(&self) -> f32 {
        let d = self.displays.displays.iter().find(|d| d.primary).or(self.displays.displays.first());
        d.map_or(1.0, |d| crate::session::scale_for(d.mode.0 as i32, d.mode.1 as i32))
    }

    /// Enter on a display page's row (ADR 0170).
    fn display_action(&mut self, name: &str) -> Effect {
        let n = &mut self.displays;
        match self.row {
            0 => n.next_size(name),
            1 => n.next_rate(name),
            2 => n.next_side(name),
            3 => n.make_primary(name),
            _ => {
                if !n.toggle(name) {
                    self.say("The last display stays on.", true);
                    return Effect::Redraw;
                }
            }
        }
        Effect::Displays(self.displays.arrangement().render())
    }

    /// A click at (x, y) in logical pixels, with where things were drawn.
    pub fn click(&mut self, x: f32, y: f32, hits: &Hits, names: &[String]) -> Effect {
        self.focus_visible = false;
        if let Some(i) = hits.sidebar.iter().position(|a| a.contains(x, y)) {
            self.open_section(i);
            return Effect::Redraw;
        }
        if hits.back.is_some_and(|a| a.contains(x, y)) {
            self.back();
            return Effect::Redraw;
        }
        let Some(&(i, _)) = hits.rows.iter().find(|(_, a)| a.contains(x, y)) else { return Effect::None };
        self.focus = Focus::Content;
        match &mut self.page {
            Page::Main => {
                self.row = i;
                self.activate(i)
            }
            Page::Zones { query, .. } => match matches(names, &query.text()).get(i) {
                Some(z) => {
                    let z = String::from(*z);
                    self.go(Page::Main);
                    Effect::SetZone(z)
                }
                None => Effect::None,
            },
            Page::Network { card, same, fixed, focus, fields, .. } => {
                // The choices come first (three for a named card), then
                // the fields.
                let choices = 2 + usize::from(card != "*");
                let first = choices - 2;
                if i < choices {
                    *same = i < first;
                    *fixed = i == first + 1;
                    *focus = 0;
                } else {
                    let k = i - choices;
                    *focus = k + 1;
                    // The caret where the click is.
                    if let Some((_, x0, carets)) = hits.carets.iter().find(|c| c.0 == k) {
                        fields[k].place(slate_ui::text::boundary_at(carets, x - x0), false);
                    }
                }
                Effect::Redraw
            }
            Page::Account { name } => {
                let name = name.clone();
                self.row = i;
                self.account_action(&name)
            }
            Page::Display { name } => {
                let name = name.clone();
                self.row = i;
                self.display_action(&name)
            }
            Page::Password { focus, .. } => {
                *focus = i;
                Effect::Redraw
            }
            Page::Entry { .. } => Effect::None,
            Page::Pick { what, selected, .. } => {
                *selected = i;
                let what = what.clone();
                self.pick(what, i)
            }
            Page::Add { focus, admin, .. } => {
                *focus = i;
                match i {
                    4 => *admin = !*admin,
                    5 => return self.add_account(),
                    _ => {}
                }
                Effect::Redraw
            }
        }
    }

    /// The wheel over the zone list.
    pub fn scroll(&mut self, lines: i32, names: &[String], shown: usize) -> Effect {
        if let Page::Zones { query, first, .. } = &mut self.page {
            let found = matches(names, &query.text()).len();
            let max = found.saturating_sub(shown);
            *first = (*first as i64 + i64::from(lines) * 3).clamp(0, max as i64) as usize;
            return Effect::Redraw;
        }
        Effect::None
    }
}

/// Editing a field clears its problem.
fn clear_error(e: &mut FieldErrors, focus: usize) {
    match focus {
        1 => e.address = None,
        2 => e.gateway = None,
        _ => e.dns = None,
    }
}

/// How Network describes the settings for every card.
pub fn network_summary(c: Option<&Card>) -> (&'static str, String) {
    match c.map(|c| &c.method) {
        Some(Method::Static { addr, prefix_len, .. }) => ("Fixed address", alloc::format!("{addr}/{prefix_len}")),
        Some(Method::Off) => ("Off: the cards are left alone", String::from("off")),
        _ => ("Automatic: the network gives the address", String::from("dhcp")),
    }
}

/// Where things were drawn, for clicks.
#[derive(Clone, Debug, Default)]
pub struct Hits {
    pub sidebar: Vec<Area>,
    /// The page's rows by index: the main page's rows, the zones among the
    /// matches, the network page's choices (2, or 3 for a card of its own)
    /// and fields after them, an
    /// account's rows, a form's fields and controls.
    pub rows: Vec<(usize, Area)>,
    pub back: Option<Area>,
    /// Each network field's text start (logical x) and caret positions.
    pub carets: Vec<(usize, f32, Vec<f32>)>,
    /// How many zone rows fit.
    pub shown: usize,
}

const SIDEBAR_W: f32 = 212.0;
const PAD: f32 = 28.0;
const ROW_H: f32 = 58.0;
/// The picture chooser's rows on view at once.
const PICK_SHOWN: usize = 7;
const ZONE_H: f32 = 28.0;

/// "14:32 BST, UTC+01:00" for `zone` at `now`.
pub fn zone_line(zone: &str, zones: Option<&[u8]>, now: i64) -> String {
    let rule = Rule::resolve(zone, zones).unwrap_or(Rule::UTC);
    let tm = rule.localtime(now);
    let mut s = String::new();
    slate_rt::time::format(&tm, "%H:%M %Z", &mut s);
    let m = tm.offset.unsigned_abs() / 60;
    if tm.offset != 0 {
        s.push_str(&alloc::format!(", UTC{}{:02}:{:02}", if tm.offset < 0 { '-' } else { '+' }, m / 60, m % 60));
    }
    s
}

/// A switch, 36 × 20: on is a chalk track with the knob at the right.
fn switch(p: &mut Painter<'_>, pal: &Palette, x: f32, y: f32, on: bool) {
    let track = Area::new(x, y, 36.0, 20.0);
    if on {
        p.fill(track, 10.0, pal.chalk);
        p.fill(Area::new(x + 19.0, y + 3.0, 14.0, 14.0), 7.0, pal.window);
    } else {
        p.fill(track, 10.0, pal.raised);
        p.border(track, 10.0, 1.0, pal.border_strong);
        p.fill(Area::new(x + 3.0, y + 3.0, 14.0, 14.0), 7.0, pal.muted);
    }
}

/// The time zones to show: their names, the table's text, and the time
/// for the zone lines.
#[derive(Clone, Copy, Debug)]
pub struct Zones<'a> {
    pub names: &'a [String],
    pub table: Option<&'a [u8]>,
    pub now: i64,
}

/// The styles a page draws with.
struct Styles<'s, 'f> {
    title: slate_ui::text::Style<'s, 'f>,
    label: slate_ui::text::Style<'s, 'f>,
    name: slate_ui::text::Style<'s, 'f>,
    desc: slate_ui::text::Style<'s, 'f>,
    mono: slate_ui::text::Style<'s, 'f>,
}

/// A row's chosen look: raised, with the focus outline when keys are in
/// use.
fn chosen_row(p: &mut Painter<'_>, pal: &Palette, a: Area, outline: bool) {
    p.fill(a, 9.0, pal.raised);
    if outline {
        p.border(a.grow(2.0), 11.0, 2.0, pal.chalk);
    }
}

/// A text field: its box, the text (dots for a secret one), the
/// selection by inversion and the caret when focused. Returns the text's
/// start and the caret positions.
fn field(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    a: Area,
    e: &LineEdit,
    focused: bool,
    bad: bool,
) -> (f32, Vec<f32>) {
    p.fill(a, 8.0, pal.well);
    let edge = if bad {
        pal.accents.clay.border
    } else if focused {
        pal.field_focus
    } else {
        pal.border
    };
    p.border(a, 8.0, 1.0, edge);
    let typed = p.style(&f.mono, 13.0, pal.text_1).ligatures(false);
    let text = if e.secret { "•".repeat(e.len()) } else { e.text() };
    // The caret positions (each character its own glyph), scrolled to
    // keep the caret in the field.
    let mut carets = alloc::vec![0.0];
    let mut prefix = String::new();
    for c in text.chars() {
        prefix.push(c);
        carets.push(p.measure(&typed, &prefix));
    }
    let caret = carets[e.caret().min(carets.len() - 1)];
    let scroll = if focused { (caret - (a.w - 26.0)).max(0.0) } else { 0.0 };
    let tx = a.x + 12.0 - scroll;
    let old = p.clip(a.grow(-2.0));
    let mid = a.y + (a.h - 20.0) / 2.0;
    p.line(&typed, tx, mid, 20.0, &text);
    if focused && let Some((s0, s1)) = e.selection() {
        // The selection by inversion: chalk, the text in desktop.
        let sel = Area::new(tx + carets[s0], mid - 1.0, carets[s1] - carets[s0], 22.0);
        p.fill(sel, 3.0, pal.chalk);
        let inner = p.clip(sel);
        let on = p.style(&f.mono, 13.0, pal.desktop).ligatures(false);
        p.line(&on, tx, mid, 20.0, &text);
        p.unclip(inner);
    }
    if focused {
        p.fill(Area::new(tx + caret, mid + 1.0, 2.0, 18.0), 0.0, pal.chalk);
    }
    p.unclip(old);
    (tx, carets)
}

/// A page's header: a back chevron, its title, and "esc to go back".
fn page_header(p: &mut Painter<'_>, pal: &Palette, st: &Styles<'_, '_>, x: f32, y: f32, w: f32, title: &str) -> Area {
    p.icon(Icon::ChevronLeft, x, y + 3.0, 16.0, pal.text_3);
    p.line(&st.title, x + 26.0, y, 22.0, title);
    let hw = p.measure(&st.label, "esc to go back");
    p.line(&st.label, x + w - hw, y + 3.0, 18.0, "esc to go back");
    Area::new(x - 6.0, y - 4.0, 28.0, 30.0)
}

/// A wallpaper drawn small at (x, y), `w` wide (16:10), its corners
/// rounded against `behind`.
fn thumbnail(p: &mut Painter<'_>, pal: &Palette, d: Design, a: Area, behind: Color) {
    let dev = p.device(&a);
    if dev.w <= 0 || dev.h <= 0 {
        return;
    }
    // Drawn as on a 640 × 400 screen, shrunk.
    let mut c = Canvas::new(dev.w, dev.h, pal.desktop);
    {
        let mut cache = GlyphCache::new();
        let mut tp = Painter::new(&mut c, &mut cache, dev.w as f32 / 640.0);
        slate_ui::wallpaper::draw(&mut tp, pal, Area::new(0.0, 0.0, 640.0, 400.0), d);
    }
    p.canvas.draw_image(dev.x, dev.y, dev.w, dev.h, &c.pixels);
    let mut corners = Path::rect(a.x, a.y, a.w, a.h);
    corners.extend(&Path::rounded_rect_reversed(a.x, a.y, a.w, a.h, 8.0));
    p.path(&corners, behind);
    p.border(a, 8.0, 1.0, pal.border);
}

/// A theme's card: its wallpaper, small, with its top bar and a window
/// on it.
fn style_card(p: &mut Painter<'_>, pal: &Palette, theme: Theme, a: Area) {
    let look = &theme.palette(false);
    thumbnail(p, look, theme.wallpaper(), a, pal.window);
    // The top bar: its fill (none over the wallpaper) and its logo.
    if look.topbar_fill.alpha() > 0 {
        let saved = p.clip(Area::new(a.x, a.y, a.w, 11.0));
        p.fill(a, 8.0, look.topbar_fill);
        p.unclip(saved);
    }
    p.fill(Area::new(a.x + 6.0, a.y + 4.0, 14.0, 3.0), 1.5, look.topbar_logo);
    // A focused window: its title bar with the glyph, two lines of text
    // and a selected row.
    let win = Area::new(a.x + a.w * 0.16, a.y + a.h * 0.26, a.w * 0.68, a.h * 0.6);
    p.fill(win, 5.0, look.window);
    let saved = p.clip(Area::new(win.x, win.y, win.w, 9.0));
    p.fill(win, 5.0, look.titlebar);
    p.unclip(saved);
    p.fill(Area::new(win.x + 1.0, win.y + 9.0, win.w - 2.0, 1.0), 0.0, look.titlebar_groove);
    p.fill(Area::new(win.x + 5.0, win.y + 3.0, 3.0, 3.0), 1.5, look.title_glyph);
    p.fill(Area::new(win.x + 11.0, win.y + 3.5, win.w * 0.3, 2.0), 1.0, look.title_text);
    p.fill(Area::new(win.x + 6.0, win.y + 15.0, win.w * 0.5, 3.0), 1.5, look.text_3);
    p.fill(Area::new(win.x + 6.0, win.y + 22.0, win.w - 12.0, 7.0), 2.0, look.list_selected);
    p.fill(Area::new(win.x + 9.0, win.y + 24.5, win.w * 0.35, 2.0), 1.0, look.window);
    p.border(win, 5.0, 1.0, look.focus);
}

/// Draw the app in `c`.
pub fn draw(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, c: Area, v: &View, z: Zones<'_>) -> Hits {
    let mut hits = Hits::default();
    // The sidebar.
    let side = Area::new(c.x, c.y, SIDEBAR_W, c.h);
    p.fill(side, 0.0, pal.well);
    p.fill(Area::new(side.right() - 1.0, c.y, 1.0, c.h), 0.0, pal.divider);
    let title = p.style(&f.medium, 15.0, pal.chalk);
    p.icon(Icon::Sliders, c.x + 20.0, c.y + 20.0, 16.0, pal.text_3);
    p.line(&title, c.x + 46.0, c.y + 18.0, 20.0, "Settings");
    let mut y = c.y + 58.0;
    for (i, s) in SECTIONS.iter().enumerate() {
        let row = Area::new(c.x + 10.0, y, SIDEBAR_W - 20.0, 34.0);
        let chosen = i == v.section;
        let (fg, icon) = if chosen && v.focus == Focus::Sidebar && v.focus_visible {
            p.fill(row, 7.0, pal.chalk);
            (pal.desktop, pal.desktop)
        } else if chosen {
            p.fill(row, 7.0, pal.raised);
            (pal.chalk, pal.text_3)
        } else {
            (pal.text_2, pal.text_4)
        };
        p.icon(s.icon(), row.x + 10.0, row.y + 9.0, 16.0, icon);
        let st = p.style(&f.regular, 13.5, fg);
        p.line(&st, row.x + 36.0, row.y, row.h, s.title());
        hits.sidebar.push(row);
        y += 36.0;
    }
    // The content.
    let x = c.x + SIDEBAR_W + PAD;
    let w = c.w - SIDEBAR_W - 2.0 * PAD;
    let area = Area::new(x, c.y, w, c.h);
    let st = Styles {
        title: p.style(&f.medium, 18.0, pal.chalk),
        label: p.style(&f.mono, 11.0, pal.muted),
        name: p.style(&f.medium, 14.0, pal.text_1),
        desc: p.style(&f.regular, 12.5, pal.muted),
        mono: p.style(&f.mono, 12.5, pal.text_3),
    };
    match &v.page {
        Page::Main => main_page(p, pal, f, &st, area, v, z, &mut hits),
        Page::Zones { query, selected, first } => {
            hits.back = Some(page_header(p, pal, &st, x, c.y + 20.0, w, "Time zone"));
            zones_page(p, pal, f, &st, area, (query, *selected, *first), z, &mut hits);
        }
        Page::Network { card, same, fixed, fields, focus, errors } => {
            hits.back = Some(page_header(p, pal, &st, x, c.y + 20.0, w, "Network"));
            network_page(p, pal, f, &st, area, v, (card, *same, *fixed, fields, *focus, errors), &mut hits);
        }
        Page::Account { name } => {
            let a = v.accounts.iter().find(|a| a.name == *name);
            let shown = a.map_or(name.as_str(), Account::shown);
            hits.back = Some(page_header(p, pal, &st, x, c.y + 20.0, w, shown));
            account_page(p, pal, f, &st, area, v, name, &mut hits);
        }
        Page::Display { name } => {
            hits.back = Some(page_header(p, pal, &st, x, c.y + 20.0, w, name));
            display_page(p, pal, &st, area, v, name, &mut hits);
        }
        Page::Password { name, fields, focus, error } => {
            hits.back = Some(page_header(p, pal, &st, x, c.y + 20.0, w, "Change the password"));
            let mut y = c.y + 64.0;
            p.line(&st.desc, x, y, 18.0, &alloc::format!("A new password for {name}."));
            y += 34.0;
            for (i, label) in ["New password", "Again"].iter().enumerate() {
                p.line(&st.label, x, y, 16.0, label);
                y += 20.0;
                let a = Area::new(x, y, w.min(420.0), 36.0);
                let bad = error.is_some() && i == *focus;
                field(p, pal, f, a, &fields[i], *focus == i, bad);
                hits.rows.push((i, a));
                y += 36.0 + 18.0;
            }
            match error {
                Some(e) => p.line(&p.style(&f.regular, 12.5, pal.accents.clay.text), x, y, 18.0, e),
                None => p.line(&st.label, x, y, 18.0, "enter to change it"),
            };
        }
        Page::Pick { what, selected, first } => {
            let face = matches!(what, Entry::Face(_));
            let title = if face { "Your picture" } else { "Your own picture" };
            hits.back = Some(page_header(p, pal, &st, x, c.y + 20.0, w, title));
            let desc = if face {
                "Pictures in your Pictures and Desktop folders and your home folder. Shown beside your name."
            } else {
                "Pictures in your Pictures and Desktop folders and your home folder. Copied, to cover the screen."
            };
            p.line(&st.desc, x, c.y + 64.0, 18.0, desc);
            let mut rows: Vec<(String, String)> = Vec::new();
            if face {
                rows.push(("No picture".into(), "Your initials instead.".into()));
            }
            for path in &v.pictures {
                let (dir, file) = path.rsplit_once('/').unwrap_or(("", path));
                let dir = match dir.strip_prefix(v.home.as_str()).filter(|_| !v.home.is_empty()) {
                    Some(rest) => alloc::format!("~{rest}"),
                    None => String::from(dir),
                };
                rows.push((String::from(file), dir));
            }
            rows.push(("Type a path…".into(), "A picture somewhere else: PNG, JPEG, GIF or BMP.".into()));
            let mut y = c.y + 96.0;
            for (k, (n, d)) in rows.iter().enumerate().skip(*first).take(PICK_SHOWN) {
                let a = Area::new(x - 12.0, y, w + 24.0, ROW_H);
                if k == *selected {
                    chosen_row(p, pal, a, v.focus_visible);
                }
                p.line(&st.name, x, y + 9.0, 20.0, n);
                p.line(&st.desc, x, y + 30.0, 18.0, d);
                hits.rows.push((k, a));
                y += ROW_H + 4.0;
            }
            if v.pictures.is_empty() {
                p.line(&st.label, x, y + 8.0, 18.0, "No pictures found there; type a path instead.");
            }
        }
        Page::Entry { what, field: fd, error } => {
            let (title, desc, hint) = match what {
                Entry::Wallpaper => (
                    "Your own picture",
                    "A picture for the wallpaper: PNG, JPEG, GIF or BMP, up to 32 MiB. It is copied, and covers the screen.",
                    "enter to use it · esc goes back",
                ),
                Entry::Name(_) => (
                    "Full name",
                    "The name shown on the login and lock screens, and to others on this computer.",
                    "enter to change it · esc goes back",
                ),
                Entry::Face(_) => (
                    "Your picture",
                    "A picture shown beside your name on the login and lock screens. Nothing typed: no picture.",
                    "enter to use it · esc goes back",
                ),
                Entry::Port => (
                    "Open a port",
                    "Let connections from other computers in to a program listening on this port: a number, \
                     with udp before it if it isn't TCP (udp 53).",
                    "enter to open it · esc goes back",
                ),
            };
            hits.back = Some(page_header(p, pal, &st, x, c.y + 20.0, w, title));
            let mut y = c.y + 64.0;
            for (k, l) in slate_ui::text::wrap(&st.desc, desc, w * p.scale).iter().take(3).enumerate() {
                p.line(&st.desc, x, y + 20.0 * k as f32, 18.0, l);
            }
            y += 70.0;
            let label = match what {
                Entry::Name(_) => "name",
                Entry::Port => "port",
                _ => "path",
            };
            p.line(&st.label, x, y, 16.0, label);
            y += 20.0;
            let a = Area::new(x, y, w.min(520.0), 36.0);
            field(p, pal, f, a, fd, true, error.is_some());
            y += 36.0 + 18.0;
            match error {
                Some(e) => p.line(&p.style(&f.regular, 12.5, pal.accents.clay.text), x, y, 18.0, e),
                None => p.line(&st.label, x, y, 18.0, hint),
            };
        }
        Page::Add { fields, admin, focus, error, .. } => {
            hits.back = Some(page_header(p, pal, &st, x, c.y + 20.0, w, "Add an account"));
            add_page(p, pal, f, &st, area, (fields, *admin, *focus, error.as_ref()), v.focus_visible, &mut hits);
        }
    }
    if !v.status.is_empty() {
        let colour = if v.status_bad { pal.accents.clay.text } else { pal.muted };
        let s = p.style(&f.regular, 12.5, colour);
        p.line(&s, x, c.bottom() - 34.0, 18.0, &v.status);
    }
    hits
}

/// A section's own page.
#[allow(clippy::too_many_arguments)]
fn main_page(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    st: &Styles<'_, '_>,
    c: Area,
    v: &View,
    z: Zones<'_>,
    hits: &mut Hits,
) {
    let (x, w) = (c.x, c.w);
    let section = v.current();
    let mut y = c.y + 20.0;
    p.line(&st.title, x, y, 22.0, section.title());
    y += 26.0;
    p.line(&st.desc, x, y, 18.0, section.blurb());
    y += 36.0;
    let keyed = v.focus == Focus::Content && v.focus_visible;
    let s = &v.settings;
    // A row with a name, a line under it, and what is on its right.
    let row = |p: &mut Painter<'_>, hits: &mut Hits, i: usize, y: f32, name: &str, desc: &str| -> Area {
        let a = Area::new(x - 12.0, y, w + 24.0, ROW_H);
        if v.focus == Focus::Content && i == v.row {
            chosen_row(p, pal, a, keyed);
        }
        p.line(&st.name, x, y + 9.0, 20.0, name);
        p.line(&st.desc, x, y + 30.0, 18.0, desc);
        hits.rows.push((i, a));
        a
    };
    let value = |p: &mut Painter<'_>, a: Area, text: &str, chevron: bool| {
        let vw = p.measure(&st.mono, text);
        let right = a.right() - 12.0 - if chevron { 22.0 } else { 0.0 };
        p.line(&st.mono, right - vw, a.y + 19.0, 20.0, text);
        if chevron {
            p.icon(Icon::ChevronRight, a.right() - 28.0, a.y + 21.0, 16.0, pal.text_4);
        }
    };
    match section {
        Section::Appearance => {
            p.line(&st.label, x, y, 16.0, "theme");
            y += 24.0;
            let n = Theme::ALL.len() as f32;
            let cw = ((w - (n - 1.0) * 16.0) / n).min(200.0);
            let ch = round(cw * 0.6);
            for (i, theme) in Theme::ALL.iter().enumerate() {
                let card = Area::new(x + i as f32 * (cw + 16.0), y, cw, ch);
                style_card(p, pal, *theme, card);
                selection_marks(p, pal, card, s.theme == *theme, keyed && v.row == i);
                p.line(&st.name, card.x, card.bottom() + 8.0, 20.0, theme.name());
                hits.rows.push((i, Area::new(card.x, card.y, card.w, card.h + 30.0)));
            }
            y += ch + 30.0 + 22.0;
            p.line(&st.label, x, y, 16.0, "wallpaper");
            y += 24.0;
            let tw = (w - (WALL_COLS - 1) as f32 * 16.0) / WALL_COLS as f32;
            let th = tw * 0.625;
            for (k, d) in Design::ALL.iter().enumerate() {
                let (col, line) = (k % WALL_COLS, k / WALL_COLS);
                let a = Area::new(x + col as f32 * (tw + 16.0), y + line as f32 * (th + 40.0), tw, th);
                thumbnail(p, &v.settings.palette(), *d, a, pal.window);
                selection_marks(p, pal, a, s.wallpaper == *d && !s.picture, keyed && v.row == STYLES + k);
                p.line(&st.desc, a.x, a.bottom() + 7.0, 18.0, d.name());
                hits.rows.push((STYLES + k, Area::new(a.x, a.y, a.w, a.h + 28.0)));
            }
            // A picture of one's own, after the designs.
            let k = Design::ALL.len();
            let (col, line) = (k % WALL_COLS, k / WALL_COLS);
            let a = Area::new(x + col as f32 * (tw + 16.0), y + line as f32 * (th + 40.0), tw, th);
            match &v.picture {
                Some(img) => crate::faces::draw(p, img, a, 8.0),
                None => {
                    p.fill(a, 8.0, pal.raised);
                    p.border(a, 8.0, 1.0, pal.border);
                    p.icon(Icon::Picture, a.x + (a.w - 20.0) / 2.0, a.y + (a.h - 20.0) / 2.0, 20.0, pal.text_3);
                }
            }
            selection_marks(p, pal, a, s.picture, keyed && v.row == STYLES + k);
            p.line(&st.desc, a.x, a.bottom() + 7.0, 18.0, "Your picture…");
            hits.rows.push((STYLES + k, Area::new(a.x, a.y, a.w, a.h + 28.0)));
        }
        Section::Accessibility => {
            let items = [
                ("High contrast", "A brighter focus outline, stronger borders and text.", s.high_contrast),
                ("Dim unfocused windows", "Windows without the keyboard shown at 85%.", s.dim),
                ("Reduce motion", "Switch, open and close without animation.", s.reduced_motion),
            ];
            for (i, (n, d, on)) in items.iter().enumerate() {
                let a = row(p, hits, i, y, n, d);
                switch(p, pal, a.right() - 12.0 - 36.0, a.y + 19.0, *on);
                y += ROW_H + 4.0;
            }
        }
        Section::DateTime => {
            let now = zone_line(&v.zone, z.table, z.now);
            let a = row(p, hits, 0, y, "Time zone", &now);
            value(p, a, &v.zone, true);
        }
        Section::Network => {
            let (d, val) = network_summary(v.network.as_ref());
            let a = row(p, hits, 0, y, "Every card", d);
            value(p, a, &val, true);
            y += ROW_H + 4.0;
            for (k, card) in v.cards.iter().enumerate() {
                let (d, val) = match v.card_settings(card) {
                    Some(c) => network_summary(Some(c)),
                    None => ("As every card", String::from("as every card")),
                };
                let a = row(p, hits, k + 1, y, card, d);
                value(p, a, &val, true);
                y += ROW_H + 4.0;
            }
        }
        Section::Bluetooth => {
            let Some(b) = &v.bluetooth else {
                p.line(&st.desc, x, y, 18.0, "The Bluetooth service isn't running.");
                return;
            };
            if b.state == "none" {
                p.line(&st.name, x, y, 20.0, "No Bluetooth adapter");
                p.line(&st.desc, x, y + 22.0, 18.0, "This computer has no Bluetooth adapter Slate can use.");
                return;
            }
            let desc = match b.state.as_str() {
                "on" => {
                    alloc::format!("Others nearby can find it as \u{201c}{}\u{201d} while this page is open.", b.name)
                }
                "starting" => String::from("Starting…"),
                "failed" => alloc::format!("It failed: {}.", b.problem),
                _ => String::from("Off: no devices connect, and nothing looks for them."),
            };
            let a = row(p, hits, 0, y, "Bluetooth", &desc);
            switch(p, pal, a.right() - 12.0 - 36.0, a.y + 19.0, b.on());
            y += ROW_H + 12.0;
            if !b.on() {
                return;
            }
            y = bluetooth_prompt(p, pal, f, st, x, y, w, b);
            let devices = v.bt_devices();
            let paired = devices.iter().filter(|d| d.paired).count();
            for (i, d) in devices.iter().enumerate() {
                if i == 0 && paired > 0 {
                    p.line(&st.label, x, y, 16.0, "paired devices");
                    y += 24.0;
                }
                if i == paired {
                    y += if paired > 0 { 10.0 } else { 0.0 };
                    let l = if b.discovering { "nearby · looking…" } else { "nearby" };
                    p.line(&st.label, x, y, 16.0, l);
                    y += 24.0;
                }
                let words = match (d.connected, d.paired, b.busy == Some(d.addr)) {
                    (_, _, true) => "pairing…",
                    (true, _, _) => "connected",
                    (false, true, _) => "paired",
                    _ => "",
                };
                let desc = if words.is_empty() {
                    String::from(d.kind.word())
                } else {
                    alloc::format!("{} · {words}", d.kind.word())
                };
                let a = row(p, hits, i + 1, y, &d.name, &desc);
                let busy = b.busy == Some(d.addr);
                let right = match (d.paired, busy) {
                    (_, true) => "",
                    (true, _) if v.removing && v.row == i + 1 => "enter to forget",
                    (true, _) => "",
                    (false, _) => "pair",
                };
                value(p, a, right, !d.paired && !busy);
                y += ROW_H + 4.0;
            }
            if paired == devices.len() {
                y += if paired > 0 { 10.0 } else { 0.0 };
                let l = if b.discovering { "nearby · looking…" } else { "nearby: nothing found (r looks again)" };
                p.line(&st.label, x, y, 16.0, l);
            }
        }
        Section::Users => {
            for (i, acc) in v.accounts.iter().enumerate() {
                let a = Area::new(x - 12.0, y, w + 24.0, ROW_H);
                if v.focus == Focus::Content && i == v.row {
                    chosen_row(p, pal, a, keyed);
                }
                avatar(p, pal, f, x, y + 11.0, acc.shown(), v.face(&acc.name));
                p.line(&st.name, x + 48.0, y + 9.0, 20.0, acc.shown());
                let kind = if acc.admin { "administrator" } else { "standard" };
                let line = alloc::format!("{} · {kind}", acc.name);
                let lw = p.line(&st.desc, x + 48.0, y + 30.0, 18.0, &line);
                if acc.name == v.me {
                    let tag = p.style(&f.mono, 10.5, pal.text_4);
                    let t = Area::new(x + 48.0 + lw + 8.0, y + 30.0, p.measure(&tag, "you") + 12.0, 18.0);
                    p.border(t, 4.0, 1.0, pal.border_strong);
                    p.line(&tag, t.x + 6.0, t.y, t.h, "you");
                }
                p.icon(Icon::ChevronRight, a.right() - 28.0, a.y + 21.0, 16.0, pal.text_4);
                hits.rows.push((i, a));
                y += ROW_H + 4.0;
            }
            let i = v.accounts.len();
            let a = Area::new(x - 12.0, y, w + 24.0, ROW_H);
            if v.focus == Focus::Content && i == v.row {
                chosen_row(p, pal, a, keyed);
            }
            p.border(Area::new(x, y + 11.0, 36.0, 36.0), 18.0, 1.0, pal.border_strong);
            p.icon(Icon::People, x + 10.0, y + 21.0, 16.0, pal.text_3);
            p.line(&st.name, x + 48.0, y + 9.0, 20.0, "Add an account");
            p.line(&st.desc, x + 48.0, y + 30.0, 18.0, "For someone else who uses this computer.");
            hits.rows.push((i, a));
            if v.accounts.is_empty() {
                p.line(&st.desc, x, y + ROW_H + 12.0, 18.0, "No one has an account of their own yet.");
            }
        }
        Section::Security => {
            let sec = &v.security;
            if let Some(on) = sec.compat {
                let a = row(
                    p,
                    hits,
                    0,
                    y,
                    "Linux compatibility",
                    "Linux programs run beside Slate's own, apart from them.",
                );
                switch(p, pal, a.right() - 12.0 - 36.0, a.y + 19.0, on);
                y += ROW_H + 4.0;
            }
            let first = sec.compat_rows();
            let fw_on = sec.firewall.unwrap_or(true);
            let a = row(
                p,
                hits,
                first,
                y,
                "Firewall",
                if fw_on {
                    "Connections from other computers are refused, unless to a port opened below."
                } else {
                    "Off: every connection from other computers comes in."
                },
            );
            switch(p, pal, a.right() - 12.0 - 36.0, a.y + 19.0, fw_on);
            y += ROW_H + 4.0;
            for (k, &(tcp, port)) in sec.ports.iter().enumerate() {
                let name = alloc::format!("{} port {port}", if tcp { "TCP" } else { "UDP" });
                let a = row(p, hits, first + 1 + k, y, &name, port_use(tcp, port));
                let closing = v.removing && v.row == first + 1 + k;
                value(p, a, if closing { "enter to close" } else { "open" }, false);
                y += ROW_H + 4.0;
            }
            let a = row(p, hits, sec.rows() - 1, y, "Open a port", "For a program that others reach on this computer.");
            value(p, a, "add", false);
            y += ROW_H + 18.0;
            let facts: [(&str, &str, &str); 3] = [
                ("Slate mode", "Slate's signed programs run apart: Linux ones can't see, signal or change them.", "on"),
                (
                    "System image",
                    if sec.devmode {
                        "Developer mode: root may change the system's files."
                    } else {
                        "Signed, and read-only for everyone, root included."
                    },
                    if sec.devmode { "writable" } else { "sealed" },
                ),
                (
                    "Disk encryption",
                    if sec.encrypted {
                        "The system disk is encrypted; it opens with a password at boot."
                    } else {
                        "The system disk is not encrypted."
                    },
                    if sec.encrypted { "on" } else { "off" },
                ),
            ];
            let well = Area::new(x - 12.0, y, w + 24.0, 16.0 + 52.0 * facts.len() as f32);
            // The page doesn't scroll: with many ports open, the facts
            // give way to them.
            if well.bottom() > c.bottom() - 44.0 {
                return;
            }
            p.fill(well, 9.0, pal.well);
            p.border(well, 9.0, 1.0, pal.active_ws);
            y += 8.0;
            for (n, d, val) in facts {
                p.line(&st.name, x, y + 6.0, 20.0, n);
                p.line(&st.desc, x, y + 26.0, 18.0, d);
                let vw = p.measure(&st.mono, val);
                p.line(&st.mono, well.right() - 14.0 - vw, y + 15.0, 20.0, val);
                y += 52.0;
            }
        }
        Section::Session => {
            let a = row(p, hits, 0, y, "Lock the screen", "After this long without the keyboard or the pointer.");
            value(p, a, &crate::settings::lock_text(s.lock), false);
            y += ROW_H + 4.0;
            let a = row(p, hits, 1, y, "Strata", "Remove it: logins after this one are on the text console.");
            value(p, a, if v.removing { "enter to remove" } else { "installed" }, false);
        }
        Section::Displays => {
            let n = &v.displays;
            if n.displays.is_empty() {
                p.line(&st.desc, x, y, 18.0, "Strata hasn't said which displays it found.");
                return;
            }
            y = arrangement_picture(p, pal, st, Area::new(x, y, w, 150.0), n) + 18.0;
            for (i, d) in n.displays.iter().enumerate() {
                let what = if d.lit {
                    alloc::format!(
                        "{} × {} at {} Hz{}",
                        d.mode.0,
                        d.mode.1,
                        d.mode.2,
                        if d.primary { " · primary" } else { "" }
                    )
                } else {
                    String::from("off")
                };
                let a = row(p, hits, i, y, &d.name, &what);
                value(p, a, "", true);
                y += ROW_H + 4.0;
            }
            let a = row(p, hits, n.displays.len(), y, "Scale", "How big everything is drawn, on every display.");
            value(p, a, &n.scale_words(), false);
            if let Some(g) = v.graphics {
                y += ROW_H + 4.0;
                let a = row(
                    p,
                    hits,
                    n.displays.len() + 1,
                    y,
                    "Graphics",
                    "SlateOS only, or full graphics with AMD's firmware.",
                );
                value(p, a, g.words(v.removing), false);
            }
        }
        Section::About => {
            p.logo(x, y, 30.0, pal.chalk);
            let big = p.style(&f.medium, 22.0, pal.chalk);
            let release = v.about.first().map_or("Slate", |r| r.1.as_str());
            p.line(&big, x + 44.0, y, 30.0, release);
            y += 54.0;
            for (k, val) in v.about.iter().skip(1) {
                p.line(&st.label, x, y + 2.0, 18.0, k);
                p.line(&st.mono, x + 140.0, y, 22.0, val);
                y += 28.0;
            }
        }
    }
}

/// A pairing's question or passkey, in steel (STRATA_COLORS.md:
/// information); returns where the page goes on below it.
#[allow(clippy::too_many_arguments)]
fn bluetooth_prompt(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    st: &Styles<'_, '_>,
    x: f32,
    y: f32,
    w: f32,
    b: &slate_bluetooth::proto::Snapshot,
) -> f32 {
    use slate_bluetooth::host::Prompt;
    let Some(prompt) = b.prompt else { return y };
    let name = b.device(prompt.addr()).map_or_else(|| alloc::format!("{}", prompt.addr()), |d| d.name.clone());
    let digits = |v: u32| {
        let s = alloc::format!("{v:06}");
        alloc::format!("{} {}", &s[..3], &s[3..])
    };
    let (ask, number, hint) = match prompt {
        Prompt::Confirm(_, v) => {
            (alloc::format!("Does this number show on {name}?"), Some(digits(v)), "enter: yes, pair · esc: no")
        }
        Prompt::Pair(_) => (alloc::format!("Pair with {name}?"), None, "enter: pair · esc: no"),
        Prompt::Passkey(_, v) => (alloc::format!("Type this on {name}, then its Enter key."), Some(digits(v)), ""),
    };
    let steel = pal.accents.steel;
    let h = 78.0 + if number.is_some() { 40.0 } else { 0.0 } - if hint.is_empty() { 22.0 } else { 0.0 };
    let card = Area::new(x - 12.0, y, w + 24.0, h);
    p.fill(card, 10.0, steel.tint);
    p.border(card, 10.0, 1.0, steel.border);
    p.icon(Icon::Bluetooth, x, y + 16.0, 18.0, steel.text);
    p.line(&st.name, x + 30.0, y + 14.0, 22.0, &ask);
    let mut yy = y + 44.0;
    if let Some(n) = number {
        let big = p.style(&f.mono, 30.0, pal.chalk);
        p.line(&big, x + 30.0, yy, 40.0, &n);
        yy += 44.0;
    }
    if !hint.is_empty() {
        p.line(&st.label, x + 30.0, yy, 18.0, hint);
    }
    y + h + 16.0
}

/// The chosen choice's outline and check; the keyboard's outline.
fn selection_marks(p: &mut Painter<'_>, pal: &Palette, a: Area, chosen: bool, keyed: bool) {
    if chosen {
        p.border(a.grow(3.0), 11.0, 2.0, pal.chalk);
        let badge = Area::new(a.right() - 26.0, a.y + 8.0, 18.0, 18.0);
        p.fill(badge, 9.0, pal.chalk);
        p.icon(Icon::Check, badge.x + 3.0, badge.y + 3.0, 12.0, pal.desktop);
    }
    if keyed {
        p.border(a.grow(7.0), 14.0, 1.5, pal.focus);
    }
}

/// A person's initials in a circle, heather (STRATA_COLORS.md: the one
/// personal accent).
fn avatar(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    x: f32,
    y: f32,
    name: &str,
    face: Option<&slate_image::Image>,
) {
    let h = pal.accents.heather;
    let a = Area::new(x, y, 36.0, 36.0);
    if let Some(img) = face {
        crate::faces::draw(p, img, a, 18.0);
        return;
    }
    p.fill(a, 18.0, h.tint);
    p.border(a, 18.0, 1.0, h.border);
    let initials: String =
        name.split_whitespace().take(2).filter_map(|w| w.chars().next()).flat_map(char::to_uppercase).collect();
    let st = p.style(&f.medium, 13.0, h.text);
    let iw = p.measure(&st, &initials);
    p.line(&st, x + (36.0 - iw) / 2.0, y, 36.0, &initials);
}

/// The time zone list.
#[allow(clippy::too_many_arguments)]
fn zones_page(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    st: &Styles<'_, '_>,
    c: Area,
    (edit, selected, first): (&LineEdit, usize, usize),
    z: Zones<'_>,
    hits: &mut Hits,
) {
    let (x, w) = (c.x, c.w);
    let mut y = c.y + 64.0;
    let field = Area::new(x, y, w, 42.0);
    p.fill(field, 8.0, pal.well);
    p.border(field, 8.0, 1.0, pal.field_focus);
    p.icon(Icon::Search, x + 14.0, y + 13.0, 16.0, pal.muted);
    let typed = p.style(&f.regular, 14.0, pal.text_1);
    let query = edit.text();
    let query = query.as_str();
    let upto = |p: &Painter<'_>, n: usize| -> f32 {
        let s: String = query.chars().take(n).collect();
        p.measure(&typed, &s)
    };
    if query.is_empty() {
        let ghost = p.style(&f.regular, 14.0, pal.muted);
        p.line(&ghost, x + 44.0, y + 11.0, 20.0, "Type a city or region");
    } else {
        if let Some((a, b)) = edit.selection() {
            let (xa, xb) = (upto(p, a), upto(p, b));
            p.fill(Area::new(x + 40.0 + xa, y + 10.0, xb - xa, 22.0), 3.0, pal.raised);
        }
        p.line(&typed, x + 40.0, y + 11.0, 20.0, query);
    }
    let cx = x + 40.0 + upto(p, edit.caret());
    p.fill(Area::new(cx + 1.0, y + 12.0, 2.0, 18.0), 0.0, pal.chalk);
    y += 42.0 + 12.0;
    let found = matches(z.names, query);
    let bottom = c.bottom() - 40.0;
    hits.shown = (((bottom - y) / ZONE_H).max(0.0)) as usize;
    // Keep the chosen one in view.
    let first = if selected < first {
        selected
    } else if hits.shown > 0 && selected >= first + hits.shown {
        selected + 1 - hits.shown
    } else {
        first
    };
    if found.is_empty() {
        p.line(&st.desc, x, y + 4.0, 20.0, "No time zone has that name.");
    }
    for (i, name) in found.iter().enumerate().skip(first).take(hits.shown) {
        let a = Area::new(x - 8.0, y, w + 16.0, ZONE_H);
        let chosen = i == selected;
        if chosen {
            p.fill(a, 6.0, pal.list_selected);
        }
        let (fg, meta) = if chosen { (pal.window, pal.window) } else { (pal.text_1, pal.muted) };
        let s = p.style(&f.mono, 12.5, fg);
        p.line(&s, x, y + 4.0, 20.0, name);
        let line = zone_line(name, z.table, z.now);
        let s = p.style(&f.mono, 11.5, meta);
        let lw = p.measure(&s, &line);
        p.line(&s, x + w - lw, y + 5.0, 18.0, &line);
        hits.rows.push((i, a));
        y += ZONE_H;
    }
}

/// The network page.
#[allow(clippy::too_many_arguments)]
fn network_page(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    st: &Styles<'_, '_>,
    c: Area,
    v: &View,
    (card, same, fixed, fields, focus, errors): (&str, bool, bool, &[LineEdit; 3], usize, &FieldErrors),
    hits: &mut Hits,
) {
    let (x, w) = (c.x, c.w);
    let mut y = c.y + 64.0;
    p.line(&st.label, x, y, 16.0, if card == "*" { "every card" } else { card });
    y += 24.0;
    let mut choices = alloc::vec![
        ("Automatic (DHCP)", "The network gives this computer its address."),
        ("Fixed address", "Set the address, gateway and name servers."),
    ];
    if card != "*" {
        choices.insert(0, ("As every card", "This card follows the settings for every card."));
    }
    let first = choices.len() - 2;
    let at = if same { 0 } else { first + usize::from(fixed) };
    for (i, (n, d)) in choices.iter().enumerate() {
        let a = Area::new(x - 12.0, y, w + 24.0, ROW_H);
        let chosen = i == at;
        if chosen {
            chosen_row(p, pal, a, v.focus_visible && focus == 0);
        }
        // A radio: a ring, filled when chosen.
        let dot = Area::new(x, y + 21.0, 16.0, 16.0);
        p.border(dot, 8.0, 1.5, if chosen { pal.chalk } else { pal.border_strong });
        if chosen {
            p.fill(Area::new(x + 4.0, y + 25.0, 8.0, 8.0), 4.0, pal.chalk);
        }
        p.line(&st.name, x + 28.0, y + 9.0, 20.0, n);
        p.line(&st.desc, x + 28.0, y + 30.0, 18.0, d);
        hits.rows.push((i, a));
        y += ROW_H + 4.0;
    }
    if fixed {
        y += 10.0;
        let names = ["Address", "Gateway", "Name servers"];
        let problems = [errors.address, errors.gateway, errors.dns];
        let bad = p.style(&f.regular, 12.0, pal.accents.clay.text);
        for i in 0..3 {
            p.line(&st.label, x, y, 16.0, names[i]);
            y += 20.0;
            let a = Area::new(x, y, w, 36.0);
            let (tx, carets) = field(p, pal, f, a, &fields[i], focus == i + 1, problems[i].is_some());
            hits.carets.push((i, tx, carets));
            hits.rows.push((i + choices.len(), a));
            y += 36.0 + 5.0;
            if let Some(e) = problems[i] {
                p.line(&bad, x, y, 16.0, e);
            }
            y += 25.0;
        }
    }
    p.line(&st.label, x, y + 6.0, 18.0, "enter to apply");
}

/// The displays as boxes where they are, the primary one outlined, each
/// with its name; returns the bottom.
fn arrangement_picture(
    p: &mut Painter<'_>,
    pal: &Palette,
    st: &Styles<'_, '_>,
    a: Area,
    n: &crate::displays::Now,
) -> f32 {
    let lit: Vec<&crate::displays::Found> = n.displays.iter().filter(|d| d.lit).collect();
    let size = |d: &crate::displays::Found| (d.mode.0 as f32 / n.scale, d.mode.1 as f32 / n.scale);
    let (x0, y0) =
        (lit.iter().map(|d| d.x).min().unwrap_or(0) as f32, lit.iter().map(|d| d.y).min().unwrap_or(0) as f32);
    let x1 = lit.iter().map(|d| d.x as f32 + size(d).0).fold(x0 + 1.0, f32::max);
    let y1 = lit.iter().map(|d| d.y as f32 + size(d).1).fold(y0 + 1.0, f32::max);
    let k = ((a.w - 2.0) / (x1 - x0)).min((a.h - 2.0) / (y1 - y0));
    let well = Area::new(a.x - 12.0, a.y, a.w + 24.0, (y1 - y0) * k + 24.0);
    p.fill(well, 9.0, pal.well);
    for d in &lit {
        let (w, h) = size(d);
        let b = Area::new(
            round(a.x + (d.x as f32 - x0) * k),
            round(a.y + 12.0 + (d.y as f32 - y0) * k),
            round(w * k) - 4.0,
            round(h * k) - 4.0,
        );
        p.fill(b, 6.0, pal.raised);
        p.border(b, 6.0, if d.primary { 2.0 } else { 1.0 }, if d.primary { pal.chalk } else { pal.border_strong });
        p.line(&st.name, b.x + 12.0, b.y + 10.0, 20.0, &d.name);
        let res = alloc::format!("{} × {}", d.mode.0, d.mode.1);
        p.line(&st.mono, b.x + 12.0, b.y + 32.0, 18.0, &res);
    }
    well.bottom()
}

/// A display's page (ADR 0170).
fn display_page(
    p: &mut Painter<'_>,
    pal: &Palette,
    st: &Styles<'_, '_>,
    c: Area,
    v: &View,
    name: &str,
    hits: &mut Hits,
) {
    let (x, w) = (c.x, c.w);
    let mut y = c.y + 64.0;
    let Some(d) = v.displays.displays.iter().find(|d| d.name == name) else { return };
    let side = v.displays.side(name);
    for (i, label) in DISPLAY_ROWS.iter().enumerate() {
        let a = Area::new(x - 12.0, y, w + 24.0, ROW_H);
        if i == v.row {
            chosen_row(p, pal, a, v.focus_visible);
        }
        let (desc, val) = match i {
            0 => ("Enter for the next one it offers.", alloc::format!("{} × {}", d.mode.0, d.mode.1)),
            1 => ("At this resolution.", alloc::format!("{} Hz", d.mode.2)),
            2 if d.primary => ("The other displays are placed around it.", String::new()),
            2 => ("Beside the primary display, edge to edge.", String::from(side.map_or("", |s| s.words()))),
            3 => ("The top bar, the launcher and new windows are on it.", String::new()),
            _ => ("Off: nothing is shown on it.", String::new()),
        };
        p.line(&st.name, x, y + 9.0, 20.0, label);
        p.line(&st.desc, x, y + 30.0, 18.0, desc);
        match i {
            3 => switch(p, pal, a.right() - 12.0 - 36.0, a.y + 19.0, d.primary),
            4 => switch(p, pal, a.right() - 12.0 - 36.0, a.y + 19.0, d.lit),
            _ => {
                let vw = p.measure(&st.mono, &val);
                p.line(&st.mono, a.right() - 12.0 - vw, a.y + 19.0, 20.0, &val);
            }
        }
        hits.rows.push((i, a));
        y += ROW_H + 4.0;
    }
}

/// One account's page.
#[allow(clippy::too_many_arguments)]
fn account_page(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    st: &Styles<'_, '_>,
    c: Area,
    v: &View,
    name: &str,
    hits: &mut Hits,
) {
    let (x, w) = (c.x, c.w);
    let mut y = c.y + 64.0;
    let acc = v.accounts.iter().find(|a| a.name == name);
    let admin = acc.is_some_and(|a| a.admin);
    avatar(p, pal, f, x, y, acc.map_or(name, Account::shown), v.face(name));
    p.line(
        &st.desc,
        x + 48.0,
        y + 9.0,
        18.0,
        &alloc::format!("{name} · {}", if admin { "administrator" } else { "standard" }),
    );
    y += 56.0;
    let keyed = v.focus_visible;
    for &i in v.account_rows(name) {
        let a = Area::new(x - 12.0, y, w + 24.0, ROW_H);
        if i == v.row {
            chosen_row(p, pal, a, keyed);
        }
        let (n, d) = match i {
            ROW_ADMIN => ("Administrator", "Can change system settings and install software, after approval."),
            ROW_PASSWORD => ("Change the password", "The password to log in with, and to approve changes."),
            ROW_NAME => ("Full name", "The name shown on the login and lock screens."),
            ROW_FACE => ("Picture", "Shown beside your name on the login and lock screens."),
            ROW_EXPIRE => {
                ("Ask for a new password", "At their next login, they choose a new password before anything else.")
            }
            _ => ("Remove this account", "The account and its home folder, with every file in it."),
        };
        let name_style = if i == ROW_REMOVE { p.style(&f.medium, 14.0, pal.accents.clay.text) } else { st.name };
        p.line(&name_style, x, y + 9.0, 20.0, n);
        p.line(&st.desc, x, y + 30.0, 18.0, d);
        match i {
            ROW_ADMIN => switch(p, pal, a.right() - 12.0 - 36.0, a.y + 19.0, admin),
            ROW_PASSWORD | ROW_NAME | ROW_FACE => {
                p.icon(Icon::ChevronRight, a.right() - 28.0, a.y + 21.0, 16.0, pal.text_4)
            }
            _ => {}
        }
        hits.rows.push((i, a));
        y += ROW_H + 4.0;
    }
    if name == v.me {
        p.line(&st.desc, x, y + 8.0, 18.0, "Another administrator can change your account's rights or remove it.");
    }
}

/// The add-account form.
#[allow(clippy::too_many_arguments)]
fn add_page(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    st: &Styles<'_, '_>,
    c: Area,
    (fields, admin, focus, error): (&[LineEdit; 4], bool, usize, Option<&(usize, String)>),
    keyed: bool,
    hits: &mut Hits,
) {
    let (x, w) = (c.x, c.w.min(460.0));
    let mut y = c.y + 64.0;
    let bad = p.style(&f.regular, 12.0, pal.accents.clay.text);
    for (i, label) in ADD_FIELDS.iter().enumerate() {
        p.line(&st.label, x, y, 16.0, label);
        y += 20.0;
        let a = Area::new(x, y, w, 34.0);
        let wrong = error.filter(|e| e.0 == i);
        field(p, pal, f, a, &fields[i], focus == i, wrong.is_some());
        hits.rows.push((i, a));
        y += 34.0 + 4.0;
        if let Some((_, e)) = wrong {
            p.line(&bad, x, y, 16.0, e);
        }
        y += 18.0;
    }
    let a = Area::new(x - 12.0, y, w + 24.0, 50.0);
    if focus == 4 {
        chosen_row(p, pal, a, keyed);
    }
    p.line(&st.name, x, y + 6.0, 20.0, "Administrator");
    p.line(&st.desc, x, y + 26.0, 18.0, "Can change system settings, after approval.");
    switch(p, pal, a.right() - 12.0 - 36.0, a.y + 15.0, admin);
    hits.rows.push((4, a));
    y += 50.0 + 16.0;
    let text = p.style(&f.medium, 14.0, pal.desktop);
    let bw = p.measure(&text, "Add account") + 40.0;
    let b = Area::new(x, y, bw, 38.0);
    p.fill(b, 8.0, pal.chalk);
    if focus == 5 && keyed {
        p.border(b.grow(4.0), 12.0, 2.0, pal.chalk);
    }
    p.line(&text, b.x + 20.0, b.y, b.h, "Add account");
    hits.rows.push((5, b));
}

/// The settings for every card (/etc/slate/network's `[*]`), and the
/// sections of cards with their own.
fn system_network() -> (Option<Card>, Vec<Card>) {
    let Ok(text) = slate_rt::fs::read_file(b"/etc/slate/network") else { return (None, Vec::new()) };
    let (net, _) = slate_netconf::Network::parse(&slate_rt::lossy(&text));
    let every = net.cards().iter().find(|c| c.name == "*").cloned();
    (every, net.cards().iter().filter(|c| c.name != "*").cloned().collect())
}

/// The pictures one is likely to choose: those in ~/Pictures (and its
/// folders, one deep), ~/Desktop and the home folder, by name (at most
/// 200).
fn system_pictures() -> Vec<String> {
    let Some(home) = slate_rt::env::var(b"HOME").map(|h| String::from(slate_rt::lossy(&h))) else { return Vec::new() };
    let picture = |n: &str| {
        let n = n.to_ascii_lowercase();
        [".png", ".jpg", ".jpeg", ".gif", ".bmp"].iter().any(|e| n.ends_with(e))
    };
    let mut out = Vec::new();
    let mut dirs = alloc::vec![alloc::format!("{home}/Pictures"), alloc::format!("{home}/Desktop"), home.clone()];
    let mut k = 0;
    while k < dirs.len() && out.len() < 200 {
        let dir = dirs[k].clone();
        let mut names: Vec<(String, bool)> = slate_rt::fs::read_dir(dir.as_bytes())
            .unwrap_or_default()
            .into_iter()
            .filter(|e| !e.name.starts_with(b"."))
            .map(|e| {
                let name = String::from(slate_rt::lossy(&e.name));
                let is_dir = slate_rt::fs::stat(alloc::format!("{dir}/{name}").as_bytes()).is_ok_and(|s| s.is_dir());
                (name, is_dir)
            })
            .collect();
        names.sort();
        for (name, is_dir) in names {
            let full = alloc::format!("{dir}/{name}");
            // The Pictures folder's own folders are looked in too.
            if is_dir && k == 0 {
                dirs.push(full);
            } else if !is_dir && picture(&name) && !out.contains(&full) {
                out.push(full);
            }
        }
        k += 1;
    }
    out.truncate(200);
    out
}

/// The computer's network cards, from /proc/net/dev (but the loopback).
fn system_cards() -> Vec<String> {
    let text = slate_rt::fs::read_file(b"/proc/net/dev").unwrap_or_default();
    slate_sysinfo::load::net_counts(&slate_rt::lossy(&text)).into_iter().map(|c| c.name).collect()
}

/// The system's zone name: /etc/slate/timezone, else UTC.
fn system_zone() -> String {
    slate_rt::fs::read_file(slate_rt::tz::SETTING)
        .ok()
        .and_then(|t| slate_rt::lossy(&t).lines().next().map(|l| String::from(l.trim())))
        .filter(|z| !z.is_empty())
        .unwrap_or_else(|| String::from("UTC"))
}

/// The accounts' pictures ([`crate::faces`]).
fn system_faces(accounts: &[Account]) -> Vec<(String, slate_image::Image)> {
    accounts.iter().filter_map(|a| Some((a.name.clone(), crate::faces::load(&a.name, a.uid)?))).collect()
}

/// The wallpaper picture of one's own, small, to show in Appearance.
fn preview_picture() -> Option<slate_image::Image> {
    crate::faces::wallpaper().map(|img| crate::faces::cover(&img, 320, 200))
}

/// The accounts on this computer.
fn system_accounts() -> Vec<Account> {
    let read = |p: &[u8]| String::from(slate_rt::lossy(&slate_rt::fs::read_file(p).unwrap_or_default()));
    accounts(&read(b"/etc/passwd"), &read(b"/etc/group"))
}

/// Ask slate-btd (ADR 0113), keep what it says now, and say on stderr
/// what changed: devices found, a pairing's question, an outcome.
fn bluetooth(v: &mut View, words: &str) {
    use slate_bluetooth::host::Prompt;
    let r = slate_bluetooth::proto::request(words);
    let new = match &r {
        Ok(s) => Some(s.clone()),
        Err(_) => None,
    };
    if let Err(e) = &r
        && !words.starts_with("visible")
    {
        v.say(&alloc::format!("{e}."), true);
    }
    let old = v.bluetooth.take();
    if let Some(n) = &new {
        let o = old.clone().unwrap_or_default();
        if n.state != o.state {
            slate_rt::eprintln!("strata-settings: bluetooth: {}", n.state);
        }
        for d in &n.devices {
            if !o.devices.iter().any(|x| x.addr == d.addr) {
                slate_rt::eprintln!("strata-settings: bluetooth: found {}", d.name);
            }
        }
        if n.prompt != o.prompt
            && let Some(pr) = n.prompt
        {
            let name = n.device(pr.addr()).map_or(String::new(), |d| d.name.clone());
            match pr {
                Prompt::Confirm(_, x) => slate_rt::eprintln!("strata-settings: bluetooth: confirm {x:06} for {name}"),
                Prompt::Pair(_) => slate_rt::eprintln!("strata-settings: bluetooth: pair with {name}?"),
                Prompt::Passkey(_, x) => slate_rt::eprintln!("strata-settings: bluetooth: passkey {x:06} for {name}"),
            }
        }
        // Outcomes from before the page looked are not news.
        if old.is_some()
            && n.said != o.said
            && let Some((t, bad)) = &n.said
        {
            slate_rt::eprintln!("strata-settings: bluetooth: {t}");
            v.say(t, *bad);
        }
    }
    v.bluetooth = new;
    v.row = v.row.min(v.rows().saturating_sub(1));
}

/// Ask the broker for `action` (with `secret`, an account's new password),
/// saying so meanwhile; the outcome's words for the status line.
fn ask(action: &str, secret: &str, done: &str, not: &str) -> (bool, String) {
    match crate::agent::request(action, secret) {
        Ok(()) => (true, String::from(done)),
        Err(e) if e == "cancelled" => (false, alloc::format!("{not}.")),
        Err(e) => (false, alloc::format!("{not}: {e}")),
    }
}

pub fn main() -> i32 {
    let files = match crate::session::load_fonts() {
        Ok(f) => f,
        Err(e) => {
            slate_rt::eprintln!("strata-settings: {e}");
            return 1;
        }
    };
    let refs: [&[u8]; 5] = core::array::from_fn(|i| files[i].as_slice());
    let Some(fonts) = Fonts::new(refs) else { return 1 };
    let zones = slate_rt::fs::read_file(slate_rt::tz::ZONES).ok();
    let names = zones.as_deref().map(slate_rt::tz::names).unwrap_or_default();
    let run = || -> Result<(), String> {
        let mut conn = Connection::connect()?;
        let mut win = conn.create("settings", None)?;
        conn.set_hints(&win, (720, 560), (900, 660))?;
        // The size asked for arrives as a configure, in the loop.
        let mut cache = GlyphCache::new();
        let mut v = View::new(Settings::load(), &system_zone());
        (v.network, v.named) = system_network();
        v.cards = system_cards();
        v.home = slate_rt::env::var(b"HOME").map(|h| String::from(slate_rt::lossy(&h))).unwrap_or_default();
        v.accounts = system_accounts();
        v.faces = system_faces(&v.accounts);
        v.picture = preview_picture();
        v.me = crate::session::user_name();
        v.security = Security::read();
        v.about = slate_sysinfo::about();
        v.graphics = Graphics::now();
        v.displays = crate::displays::Now::load();
        let mut bt_open = false;
        let paint = |v: &View, win: &Window, cache: &mut GlyphCache| -> (Canvas, Hits) {
            let pal = v.settings.palette();
            let mut canvas = win.canvas(pal.window);
            let mut p = Painter::new(&mut canvas, cache, win.scale);
            let (w, h) = p.size();
            let now = slate_rt::time::unix();
            let z = Zones { names: &names, table: zones.as_deref(), now };
            let hits = draw(&mut p, &pal, &fonts, Area::new(0.0, 0.0, w, h), v, z);
            (canvas, hits)
        };
        loop {
            let (canvas, hits) = paint(&v, &win, &mut cache);
            conn.present(&mut win, &canvas)?;
            let mut effect = Effect::None;
            // Redraw at least every half minute, for the times shown (each
            // second on the Bluetooth page).
            let wait = if v.current() == Section::Bluetooth { 1000 } else { 30_000 };
            for e in conn.poll(wait)? {
                let e2 = match e {
                    Event::Close { .. } => return Ok(()),
                    Event::Configure { .. } => {
                        win.configure(&e);
                        Effect::Redraw
                    }
                    Event::Key { code, ch, mods, .. } => {
                        v.key(code, char::from_u32(ch).filter(|_| ch != 0), mods, &names)
                    }
                    Event::Paste { text, .. } => v.paste(&text),
                    Event::Pointer { kind: strata_proto::PointerKind::Down, button: 1, x, y, .. } => {
                        v.click(x as f32 / win.scale, y as f32 / win.scale, &hits, &names)
                    }
                    Event::Scroll { lines, .. } => v.scroll(lines, &names, hits.shown),
                    _ => Effect::None,
                };
                if e2 != Effect::None {
                    effect = e2;
                }
            }
            // A broker request waits for approval: say so first.
            let waiting = |v: &mut View, win: &mut Window, conn: &mut Connection, cache: &mut GlyphCache| {
                v.say("Waiting for approval…", false);
                let (canvas, _) = paint(v, win, cache);
                conn.present(win, &canvas)
            };
            // Strata's report of the displays, read again as the section
            // opens (a display may have come or gone).
            if v.current() == Section::Displays && v.page == Page::Main && v.focus == Focus::Sidebar {
                v.displays = crate::displays::Now::load();
            }
            match effect {
                Effect::Displays(text) => match crate::displays::Arrangement::parse(&text).save() {
                    Ok(()) => {
                        slate_rt::eprintln!("strata-settings: displays: {}", text.trim_end().replace('\n', "; "));
                    }
                    Err(e) => v.say(&alloc::format!("Couldn't save the arrangement: {e}"), true),
                },
                Effect::Save => {
                    match v.settings.save() {
                        Ok(()) => v.status.clear(),
                        Err(e) => v.say(&alloc::format!("Couldn't save the settings: {e}"), true),
                    }
                    slate_rt::eprintln!(
                        "strata-settings: saved: {} {}",
                        v.settings.theme.key(),
                        v.settings.wallpaper.key()
                    );
                }
                Effect::SetZone(z) => {
                    waiting(&mut v, &mut win, &mut conn, &mut cache)?;
                    let (ok, text) = ask(
                        &alloc::format!("timezone={z}"),
                        "",
                        "The time zone was changed.",
                        "The time zone was not changed",
                    );
                    if ok {
                        slate_rt::eprintln!("strata-settings: the time zone is now {z}");
                        v.zone = z;
                    }
                    v.say(&text, !ok);
                }
                Effect::SetNetwork(card) => {
                    waiting(&mut v, &mut win, &mut conn, &mut cache)?;
                    let words = card.words().join(" ");
                    let (ok, text) = ask(
                        &alloc::format!("network={words}"),
                        "",
                        "The network settings were changed.",
                        "The network settings were not changed",
                    );
                    if ok {
                        slate_rt::eprintln!("strata-settings: the network is now {words}");
                        if card.name == "*" {
                            v.network = Some(card);
                        } else {
                            v.named.retain(|c| c.name != card.name);
                            v.named.push(card);
                        }
                    }
                    v.say(&text, !ok);
                }
                Effect::NetworkDefault(name) => {
                    waiting(&mut v, &mut win, &mut conn, &mut cache)?;
                    let (ok, text) = ask(
                        &alloc::format!("network={name} default"),
                        "",
                        &alloc::format!("{name} is set as every card is."),
                        "The network settings were not changed",
                    );
                    if ok {
                        slate_rt::eprintln!("strata-settings: {name} follows every card");
                        v.named.retain(|c| c.name != name);
                    }
                    v.say(&text, !ok);
                }
                Effect::Graphics(full) => {
                    waiting(&mut v, &mut win, &mut conn, &mut cache)?;
                    let (ok, text) = if full {
                        ask(
                            "graphics=full",
                            "",
                            "Full graphics from the next start: AMD's firmware is installed.",
                            "Full graphics was not turned on",
                        )
                    } else {
                        ask(
                            "graphics=slate",
                            "",
                            "SlateOS only from the next start: AMD's firmware is removed.",
                            "Full graphics was not turned off",
                        )
                    };
                    if ok {
                        slate_rt::eprintln!("strata-settings: full graphics {}", if full { "on" } else { "off" });
                    }
                    v.graphics = Graphics::now();
                    v.say(&text, !ok);
                }
                Effect::RemoveDesktop => {
                    waiting(&mut v, &mut win, &mut conn, &mut cache)?;
                    let (ok, text) = ask(
                        "desktop=remove",
                        "",
                        "Strata is removed; it goes when you log out.",
                        "Strata was not removed",
                    );
                    if ok {
                        slate_rt::eprintln!("strata-settings: Strata is removed");
                    }
                    v.say(&text, !ok);
                }
                Effect::User(words, secret) => {
                    waiting(&mut v, &mut win, &mut conn, &mut cache)?;
                    let done = if let Some(n) = words.strip_prefix("expire ") {
                        alloc::format!("{n} chooses a new password at the next login.")
                    } else {
                        String::from("Done.")
                    };
                    let (ok, text) =
                        ask(&alloc::format!("user={words}"), &secret, &done, "The account was not changed");
                    v.accounts = system_accounts();
                    if ok {
                        // The log shows the change's words, never a password.
                        slate_rt::eprintln!("strata-settings: account change: {words}");
                        let leave = matches!(v.page, Page::Add { .. } | Page::Password { .. } | Page::Entry { .. })
                            || words.starts_with("remove ");
                        if leave {
                            v.back();
                            if words.starts_with("remove ") {
                                v.back();
                            }
                        }
                    }
                    v.say(&text, !ok);
                }
                Effect::Compat(on) => {
                    waiting(&mut v, &mut win, &mut conn, &mut cache)?;
                    let word = if on { "on" } else { "off" };
                    let (ok, text) = ask(
                        &alloc::format!("compat={word}"),
                        "",
                        &alloc::format!("Linux compatibility is {word}."),
                        "Linux compatibility was not changed",
                    );
                    if ok {
                        slate_rt::eprintln!("strata-settings: linux compatibility {word}");
                    }
                    v.security = Security::read();
                    v.say(&text, !ok);
                }
                Effect::Firewall(words) => {
                    waiting(&mut v, &mut win, &mut conn, &mut cache)?;
                    let done = match words.as_str() {
                        "on" => String::from("The firewall is on."),
                        "off" => String::from("The firewall is off."),
                        w if w.starts_with("allow") => alloc::format!("Port {} is open.", &w[6..]),
                        w => alloc::format!("Port {} is closed.", w.get(5..).unwrap_or("")),
                    };
                    let (ok, text) =
                        ask(&alloc::format!("firewall={words}"), "", &done, "The firewall was not changed");
                    if ok {
                        slate_rt::eprintln!("strata-settings: firewall {words}");
                        if matches!(v.page, Page::Entry { what: Entry::Port, .. }) {
                            v.back();
                        }
                    }
                    v.security = Security::read();
                    v.row = v.row.min(v.rows().saturating_sub(1));
                    v.say(&text, !ok);
                }
                Effect::Bluetooth(words) => {
                    slate_rt::eprintln!("strata-settings: bluetooth: asked: {words}");
                    bluetooth(&mut v, &words);
                }
                Effect::Wallpaper(path) => match crate::faces::set_wallpaper(&path) {
                    Ok(()) => {
                        v.settings.picture = true;
                        v.picture = preview_picture();
                        // Saved even when it was a picture already, so that
                        // Strata reads the new one.
                        if let Err(e) = v.settings.save() {
                            v.say(&alloc::format!("Couldn't save the settings: {e}"), true);
                        }
                        slate_rt::eprintln!("strata-settings: the wallpaper is {path}");
                        v.back();
                    }
                    Err(e) => match &mut v.page {
                        Page::Entry { error, .. } => *error = Some(e),
                        _ => v.say(&e, true),
                    },
                },
                Effect::Pictures(what) => {
                    v.pictures = system_pictures();
                    v.open_pick(what);
                }
                Effect::Face(path) => {
                    let me = v.me.clone();
                    // A file someone else left under one's name is in the
                    // way: the broker takes it away (ADR 0110).
                    if crate::faces::blocked(&me, slate_rt::process::getuid()) {
                        waiting(&mut v, &mut win, &mut conn, &mut cache)?;
                        let (ok, text) =
                            ask(&alloc::format!("user=unblock {me}"), "", "", "Your picture can't be changed");
                        if !ok {
                            v.say(&text, true);
                            continue;
                        }
                        slate_rt::eprintln!("strata-settings: someone else's file under {me}'s picture taken away");
                    }
                    let r = if path.is_empty() {
                        crate::faces::remove(&me)
                    } else {
                        crate::faces::read_picture(&path).and_then(|img| crate::faces::save(&me, &img))
                    };
                    match r {
                        Ok(()) => {
                            v.faces = system_faces(&v.accounts);
                            let what = if path.is_empty() { String::from("none") } else { path };
                            slate_rt::eprintln!("strata-settings: {me}'s picture is {what}");
                            v.back();
                        }
                        Err(e) => match &mut v.page {
                            Page::Entry { error, .. } => *error = Some(e),
                            _ => v.say(&e, true),
                        },
                    }
                }
                Effect::Copy(t) => conn.copy(slate_strata_client::clipboard::CLIPBOARD, &t)?,
                Effect::Paste => conn.paste(&win, slate_strata_client::clipboard::CLIPBOARD)?,
                Effect::None | Effect::Redraw => {}
            }
            // The Bluetooth page follows the daemon each second, keeps the
            // computer visible, and looks for devices when it opens.
            let on_page = v.current() == Section::Bluetooth;
            if on_page {
                bluetooth(&mut v, "visible on");
                if !bt_open && v.bluetooth.as_ref().is_some_and(|b| b.on()) {
                    bluetooth(&mut v, "discover");
                }
            } else if bt_open {
                bluetooth(&mut v, "visible off");
            }
            bt_open = on_page;
        }
    };
    match run() {
        Ok(()) => 0,
        Err(e) => {
            slate_rt::eprintln!("strata-settings: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Vec<String> {
        ["America/New_York", "Asia/Kolkata", "Europe/London", "Europe/Paris", "UTC"].map(String::from).to_vec()
    }

    fn typing(v: &mut View, s: &str, n: &[String]) {
        s.chars().for_each(|c| _ = v.key(0, Some(c), 0, n));
    }

    fn section(v: &mut View, s: Section, n: &[String]) {
        v.open_section(SECTIONS.iter().position(|x| *x == s).unwrap());
        v.key(KEY_RIGHT, None, 0, n);
    }

    #[test]
    fn filters() {
        let n = names();
        assert_eq!(matches(&n, "new york"), ["America/New_York"]);
        assert_eq!(matches(&n, "EUROPE"), ["Europe/London", "Europe/Paris"]);
        assert_eq!(matches(&n, "").len(), 5);
        assert!(matches(&n, "mars").is_empty());
    }

    #[test]
    fn sidebar_and_appearance() {
        let n = names();
        let mut v = View::new(Settings::default(), "UTC");
        // Down the sidebar and back; right goes into Appearance.
        v.key(KEY_DOWN, None, 0, &n);
        assert_eq!(v.current(), Section::Accessibility);
        v.key(KEY_UP, None, 0, &n);
        v.key(KEY_UP, None, 0, &n);
        assert_eq!(v.current(), Section::Appearance);
        v.key(KEY_RIGHT, None, 0, &n);
        assert_eq!((v.focus, v.row), (Focus::Content, 0));
        // Right to Light, and space chooses it.
        v.key(KEY_RIGHT, None, 0, &n);
        assert_eq!(v.key(KEY_SPACE, None, 0, &n), Effect::Save);
        assert_eq!(v.settings.theme, Theme::Light);
        // On to Sediment and Copper Noir (ADR 0167), then back to Light.
        v.key(KEY_RIGHT, None, 0, &n);
        v.key(KEY_RIGHT, None, 0, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Save);
        assert_eq!((v.settings.theme, v.settings.wallpaper), (Theme::Sediment, Design::Sediment));
        v.key(KEY_LEFT, None, 0, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Save);
        assert_eq!(v.settings.palette(), Palette::COPPER_NOIR);
        assert_eq!(v.settings.wallpaper, Design::CopperGlow);
        v.key(KEY_LEFT, None, 0, &n);
        v.key(KEY_SPACE, None, 0, &n);
        assert!(v.settings.light());
        // Down to the wallpapers under Light (Contours), down again
        // (Facets), left (Dots), up to the first row's first (Lineation),
        // then right twice (Dunes).
        v.key(KEY_DOWN, None, 0, &n);
        assert_eq!(Design::ALL[v.row - STYLES], Design::Contours);
        v.key(KEY_DOWN, None, 0, &n);
        assert_eq!(Design::ALL[v.row - STYLES], Design::Facets);
        v.key(KEY_LEFT, None, 0, &n);
        v.key(KEY_UP, None, 0, &n);
        assert_eq!(Design::ALL[v.row - STYLES], Design::Lineation);
        v.key(KEY_RIGHT, None, 0, &n);
        v.key(KEY_RIGHT, None, 0, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Save);
        assert_eq!(v.settings.wallpaper, Design::Dunes);
        // Up from the wallpapers' first row goes to the theme above
        // (Dunes, the third, to Copper Noir); Esc to the sidebar.
        v.key(KEY_UP, None, 0, &n);
        assert_eq!(Theme::ALL[v.row], Theme::CopperNoir);
        v.key(KEY_ESC, None, 0, &n);
        assert_eq!(v.focus, Focus::Sidebar);
    }

    #[test]
    fn accessibility_and_session() {
        let n = names();
        let mut v = View::new(Settings { lock: 300, ..Settings::default() }, "UTC");
        section(&mut v, Section::Accessibility, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Save);
        assert!(v.settings.high_contrast);
        v.key(KEY_DOWN, None, 0, &n);
        v.key(KEY_DOWN, None, 0, &n);
        v.key(KEY_SPACE, None, 0, &n);
        assert!(v.settings.reduced_motion && !v.settings.dim);
        // The lock steps through the idle times.
        section(&mut v, Section::Session, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Save);
        assert_eq!(v.settings.lock, 900);
        // Removing Strata takes a second Enter; moving away disarms it.
        v.key(KEY_DOWN, None, 0, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Redraw);
        assert!(v.removing && v.status_bad);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::RemoveDesktop);
        v.key(KEY_ENTER, None, 0, &n);
        v.key(KEY_UP, None, 0, &n);
        v.key(KEY_ENTER, None, 0, &n);
        assert!(!v.removing);
    }

    #[test]
    fn time_zone() {
        let n = names();
        let mut v = View::new(Settings::default(), "UTC");
        section(&mut v, Section::DateTime, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Redraw);
        typing(&mut v, "euro", &n);
        v.key(0, Some('x'), CTRL, &n);
        v.key(KEY_DOWN, None, 0, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::SetZone("Europe/Paris".into()));
        assert_eq!(v.page, Page::Main);
        v.key(KEY_ENTER, None, 0, &n);
        assert_eq!(v.key(KEY_ESC, None, 0, &n), Effect::Redraw);
        assert_eq!((&v.page, v.focus), (&Page::Main, Focus::Content));
    }

    #[test]
    fn editing_network_fields() {
        let n = names();
        let mut v = View::new(Settings::default(), "UTC");
        section(&mut v, Section::Network, &n);
        v.key(KEY_ENTER, None, 0, &n);
        v.key(KEY_RIGHT, None, 0, &n);
        // "/24" first, then the address before it.
        v.key(KEY_TAB, None, 0, &n);
        typing(&mut v, "/24", &n);
        v.key(KEY_HOME, None, 0, &n);
        typing(&mut v, "10.0.2.15", &n);
        // The gateway selected and copied to Strata's clipboard ...
        v.key(KEY_TAB, None, 0, &n);
        typing(&mut v, "10.0.2.2", &n);
        v.key(KEY_HOME, None, SHIFT, &n);
        assert_eq!(v.key(0, Some('c'), CTRL, &n), Effect::Copy("10.0.2.2".into()));
        // ... and pasted into the name servers, then changed.
        v.key(KEY_TAB, None, 0, &n);
        assert_eq!(v.key(0, Some('v'), CTRL, &n), Effect::Paste);
        assert_eq!(v.paste("10.0.2.2"), Effect::Redraw);
        v.key(KEY_BACKSPACE, None, 0, &n);
        typing(&mut v, "3", &n);
        let Effect::SetNetwork(c) = v.key(KEY_ENTER, None, 0, &n) else { panic!() };
        assert_eq!(c.words().join(" "), "* static 10.0.2.15/24 gateway 10.0.2.2 dns 10.0.2.3");
    }

    #[test]
    fn network_page() {
        let n = names();
        let mut v = View::new(Settings::default(), "UTC");
        assert_eq!(network_summary(None).1, "dhcp");
        section(&mut v, Section::Network, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Redraw);
        assert!(matches!(v.page, Page::Network { fixed: false, focus: 0, .. }));
        // Automatic: Enter asks for DHCP on every card.
        let Effect::SetNetwork(c) = v.key(KEY_ENTER, None, 0, &n) else { panic!() };
        assert_eq!(c.words().join(" "), "* dhcp");
        // Fixed: the fields, a mistake, then the change.
        v.key(KEY_ENTER, None, 0, &n);
        v.key(KEY_RIGHT, None, 0, &n);
        for (field, text) in ["10.0.2.15/24", "10.0.2.2", "10.0.2.3"].iter().enumerate() {
            v.key(KEY_TAB, None, 0, &n);
            typing(&mut v, text, &n);
            if field == 1 {
                v.key(0, Some('x'), 0, &n);
            }
        }
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Redraw);
        let Page::Network { errors, focus, .. } = &v.page else { panic!() };
        assert!(errors.gateway.is_some() && errors.address.is_none() && *focus == 2);
        v.key(KEY_END, None, 0, &n);
        v.key(KEY_BACKSPACE, None, 0, &n);
        let Effect::SetNetwork(c) = v.key(KEY_ENTER, None, 0, &n) else { panic!() };
        assert_eq!(c.words().join(" "), "* static 10.0.2.15/24 gateway 10.0.2.2 dns 10.0.2.3");
        assert_eq!(v.page, Page::Main);
        // Opened again, the page shows what is set.
        v.network = Some(c);
        assert_eq!(network_summary(v.network.as_ref()), ("Fixed address", "10.0.2.15/24".into()));
        v.key(KEY_ENTER, None, 0, &n);
        let Page::Network { fixed, fields, .. } = &v.page else { panic!() };
        assert!(*fixed && fields[1].text() == "10.0.2.2" && fields[2].text() == "10.0.2.3");
        assert_eq!(v.key(KEY_ESC, None, 0, &n), Effect::Redraw);
        assert_eq!(v.page, Page::Main);
    }

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\nada:x:1000:1000:Ada Lovelace,,,:/home/ada:/bin/sh\n\
        bo:x:1001:1001::/home/bo:/bin/sh\nsvc:x:1002:1002::/:/sbin/nologin\n";
    const GROUP: &str = "root:x:0:\nwheel:x:10:root,ada\nada:x:1000:\n";

    #[test]
    fn the_accounts() {
        let a = accounts(PASSWD, GROUP);
        assert_eq!(
            a,
            [
                Account { name: "ada".into(), full: "Ada Lovelace".into(), admin: true, uid: 1000 },
                Account { name: "bo".into(), full: String::new(), admin: false, uid: 1001 },
            ]
        );
        assert_eq!(a[1].shown(), "bo");
        assert_eq!(suggest_login("Ada Lovelace"), "ada");
        assert_eq!(suggest_login("Zoë O'Neil"), "zo");
        assert_eq!(suggest_login("42 Grace"), "");
        assert!(valid_login("ada") && valid_login("a_b-2") && !valid_login("Ada") && !valid_login("2a"));
    }

    #[test]
    fn adding_an_account() {
        let n = names();
        let mut v = View::new(Settings::default(), "UTC");
        v.accounts = accounts(PASSWD, GROUP);
        section(&mut v, Section::Users, &n);
        // Down past the two accounts to "Add an account".
        v.key(KEY_DOWN, None, 0, &n);
        v.key(KEY_DOWN, None, 0, &n);
        v.key(KEY_ENTER, None, 0, &n);
        assert!(matches!(v.page, Page::Add { focus: 0, .. }));
        // The user name follows the full name until it is typed.
        typing(&mut v, "Grace Hopper", &n);
        let Page::Add { fields, .. } = &v.page else { panic!() };
        assert_eq!(fields[1].text(), "grace");
        v.key(KEY_TAB, None, 0, &n);
        v.key(KEY_BACKSPACE, None, 0, &n);
        typing(&mut v, "y", &n);
        v.key(KEY_TAB, None, 0, &n);
        typing(&mut v, "s3cret", &n);
        v.key(KEY_ENTER, None, 0, &n);
        typing(&mut v, "s3cre", &n);
        // To the button: the passwords differ, so the second field again.
        v.key(KEY_DOWN, None, 0, &n);
        v.key(KEY_SPACE, None, 0, &n);
        v.key(KEY_DOWN, None, 0, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Redraw);
        let Page::Add { focus, error, admin, .. } = &v.page else { panic!() };
        assert_eq!((*focus, error.as_ref().map(|e| e.0), *admin), (3, Some(3), true));
        typing(&mut v, "t", &n);
        assert!(matches!(&v.page, Page::Add { error: None, .. }));
        v.key(KEY_TAB, None, 0, &n);
        v.key(KEY_TAB, None, 0, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::User("add gracy admin Grace Hopper".into(), "s3cret".into()));
        // A name that is taken.
        let Page::Add { fields, .. } = &mut v.page else { panic!() };
        fields[1].set_text("ada");
        assert_eq!(v.add_account(), Effect::Redraw);
        assert!(matches!(&v.page, Page::Add { focus: 1, error: Some((1, _)), .. }));
        // Esc back to the list, on "Add an account".
        v.key(KEY_ESC, None, 0, &n);
        assert_eq!((&v.page, v.row), (&Page::Main, 2));
    }

    #[test]
    fn changing_an_account() {
        let n = names();
        let mut v = View::new(Settings::default(), "UTC");
        v.accounts = accounts(PASSWD, GROUP);
        v.me = "ada".into();
        section(&mut v, Section::Users, &n);
        // bo: administrator, a password, removing after asking.
        v.key(KEY_DOWN, None, 0, &n);
        v.key(KEY_ENTER, None, 0, &n);
        assert_eq!(v.page, Page::Account { name: "bo".into() });
        assert_eq!(v.key(KEY_SPACE, None, 0, &n), Effect::User("admin bo".into(), String::new()));
        v.key(KEY_DOWN, None, 0, &n);
        v.key(KEY_ENTER, None, 0, &n);
        assert!(matches!(v.page, Page::Password { .. }));
        typing(&mut v, "pw", &n);
        v.key(KEY_ENTER, None, 0, &n);
        typing(&mut v, "pw", &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::User("password bo".into(), "pw".into()));
        v.key(KEY_ESC, None, 0, &n);
        assert_eq!((&v.page, v.row), (&Page::Account { name: "bo".into() }, 1));
        // A new password at the next login.
        v.key(KEY_DOWN, None, 0, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::User("expire bo".into(), String::new()));
        // The full name: typed, Enter asks the broker; Esc comes back.
        v.key(KEY_DOWN, None, 0, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Redraw);
        assert!(matches!(v.page, Page::Entry { what: Entry::Name(_), .. }));
        typing(&mut v, "Bo Diddley", &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::User("name bo Bo Diddley".into(), String::new()));
        typing(&mut v, ",", &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Redraw, "no commas");
        v.key(KEY_ESC, None, 0, &n);
        assert_eq!((&v.page, v.row), (&Page::Account { name: "bo".into() }, ROW_NAME));
        v.key(KEY_DOWN, None, 0, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Redraw);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::User("remove bo".into(), String::new()));
        // One's own account: the password, the full name and the picture.
        v.key(KEY_ESC, None, 0, &n);
        v.key(KEY_UP, None, 0, &n);
        v.key(KEY_ENTER, None, 0, &n);
        assert_eq!((&v.page, v.row), (&Page::Account { name: "ada".into() }, ROW_PASSWORD));
        v.key(KEY_DOWN, None, 0, &n);
        v.key(KEY_DOWN, None, 0, &n);
        assert_eq!(v.row, ROW_FACE);
        // The chooser: no picture, the pictures found, typing a path.
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Pictures(Entry::Face("ada".into())));
        v.pictures = alloc::vec!["/home/ada/Pictures/me.png".into()];
        v.open_pick(Entry::Face("ada".into()));
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Face(String::new()));
        v.key(KEY_DOWN, None, 0, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Face("/home/ada/Pictures/me.png".into()));
        v.key(KEY_END, None, 0, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Redraw);
        assert!(matches!(v.page, Page::Entry { what: Entry::Face(_), .. }));
        // Nothing typed: no picture.
        for _ in 0..11 {
            v.key(KEY_BACKSPACE, None, 0, &n);
        }
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Face(String::new()));
        // The wallpaper: the picture tile after the designs, the chooser
        // (nothing found: only typing a path).
        section(&mut v, Section::Appearance, &n);
        v.row = STYLES + Design::ALL.len();
        assert_eq!(v.activate(v.row), Effect::Pictures(Entry::Wallpaper));
        v.pictures.clear();
        v.open_pick(Entry::Wallpaper);
        v.key(KEY_ESC, None, 0, &n);
        assert_eq!((&v.page, v.row), (&Page::Main, STYLES + Design::ALL.len()), "back on the tile");
        v.open_pick(Entry::Wallpaper);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Redraw);
        assert!(matches!(v.page, Page::Entry { what: Entry::Wallpaper, .. }));
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Redraw, "a folder isn't a picture");
        typing(&mut v, "beach.jpg", &n);
        assert!(matches!(v.key(KEY_ENTER, None, 0, &n), Effect::Wallpaper(p) if p.ends_with("/Pictures/beach.jpg")));
    }

    #[test]
    fn security() {
        let n = names();
        let mut v = View::new(Settings::default(), "UTC");
        v.security = Security { compat: Some(true), ..Security::default() };
        section(&mut v, Section::Security, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Compat(false));
        // Without the kernel's switch, the firewall comes first: on, a
        // port that closes on a second Enter, and opening one.
        v.security = Security { firewall: Some(true), ports: alloc::vec![(true, 22)], ..Security::default() };
        v.open_section(SECTIONS.iter().position(|x| *x == Section::Security).unwrap());
        assert_eq!(v.key(KEY_RIGHT, None, 0, &n), Effect::Redraw);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Firewall("off".into()));
        assert_eq!(v.key(KEY_DOWN, None, 0, &n), Effect::Redraw);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Redraw, "asks first");
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Firewall("deny tcp 22".into()));
        assert_eq!(v.key(KEY_DOWN, None, 0, &n), Effect::Redraw);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Redraw);
        assert!(matches!(v.page, Page::Entry { what: Entry::Port, .. }));
        typing(&mut v, "seventy", &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Redraw, "not a port");
        let mut v2 = v.clone();
        v2.back();
        assert_eq!(v2.row, 2, "back on the row that opened it");
        let mut field = LineEdit::new("udp 53");
        field.place(usize::MAX, false);
        v.page = Page::Entry { what: Entry::Port, field, error: None };
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Firewall("allow udp 53".into()));
    }

    /// A card of its own: three choices, the first following every card.
    #[test]
    fn network_per_card() {
        let n = names();
        let mut v = View::new(Settings::default(), "UTC");
        v.cards = alloc::vec!["eth0".into(), "eth1".into()];
        section(&mut v, Section::Network, &n);
        assert_eq!(v.rows(), 3);
        assert_eq!(v.key(KEY_DOWN, None, 0, &n), Effect::Redraw);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Redraw);
        assert!(matches!(&v.page, Page::Network { card, same: true, fixed: false, .. } if card == "eth0"));
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::NetworkDefault("eth0".into()));
        // Automatic, then fixed.
        section(&mut v, Section::Network, &n);
        v.key(KEY_DOWN, None, 0, &n);
        v.key(KEY_DOWN, None, 0, &n);
        v.key(KEY_ENTER, None, 0, &n);
        assert!(matches!(&v.page, Page::Network { card, .. } if card == "eth1"));
        v.key(KEY_RIGHT, None, 0, &n);
        let Effect::SetNetwork(c) = v.key(KEY_ENTER, None, 0, &n) else { panic!() };
        assert_eq!((c.name.as_str(), &c.method), ("eth1", &Method::Dhcp));
        v.named.push(Card::from_words(&["eth1", "static", "10.0.0.2/24"]).unwrap());
        section(&mut v, Section::Network, &n);
        v.key(KEY_DOWN, None, 0, &n);
        v.key(KEY_DOWN, None, 0, &n);
        v.key(KEY_ENTER, None, 0, &n);
        let Page::Network { same, fixed, fields, .. } = &v.page else { panic!() };
        assert!(!same && *fixed && fields[0].text() == "10.0.0.2/24", "its own settings, filled in");
        v.key(KEY_LEFT, None, 0, &n);
        v.key(KEY_LEFT, None, 0, &n);
        assert!(matches!(v.page, Page::Network { same: true, .. }));
    }

    #[test]
    fn firewall_text() {
        assert_eq!(
            firewall_ports("# x\nallow tcp 22 # sshd\nallow udp 53\nallow tcp 22\ndeny tcp 1\n"),
            [(true, 22), (false, 53)]
        );
        assert_eq!(typed_port("8080"), Some((true, 8080)));
        assert_eq!(typed_port(" UDP 53 "), Some((false, 53)));
        assert_eq!(typed_port("53/udp"), Some((false, 53)));
        assert_eq!(typed_port("tcp/443"), Some((true, 443)));
        assert_eq!(typed_port("0"), None);
        assert_eq!(typed_port("sctp 9"), None);
        assert_eq!(typed_port("70000"), None);
    }

    /// The Bluetooth page (ADR 0113), over a state as slate-btd gives it.
    pub fn bluetooth_view() -> View {
        let mut v = View::new(Settings::default(), "UTC");
        v.bluetooth = Some(slate_bluetooth::proto::parse_snapshot(
            "state on\ncontroller C0:FF:EE:00:00:01 desk\ndiscovering yes\nvisible yes\n\
             device 00:1F:20:44:55:66 paired near keyboard Slate Keyboard\n\
             device 5C:F3:70:11:22:33 found near phone Ada's Phone\n\
             device 11:22:33:44:55:66 found near headphones Studio Headphones\n",
        ));
        v
    }

    #[test]
    fn bluetooth() {
        let n = names();
        let mut v = bluetooth_view();
        section(&mut v, Section::Bluetooth, &n);
        assert_eq!(v.rows(), 4);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Bluetooth("power off".into()));
        let names: Vec<String> = v.bt_devices().iter().map(|d| d.name.clone()).collect();
        assert_eq!(names, ["Slate Keyboard", "Ada's Phone", "Studio Headphones"], "paired first");
        // Pair the phone.
        v.key(KEY_DOWN, None, 0, &n);
        v.key(KEY_DOWN, None, 0, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Bluetooth("pair 5C:F3:70:11:22:33".into()));
        // Its question: Enter says yes, Esc no.
        let b = v.bluetooth.as_mut().unwrap();
        b.prompt = Some(slate_bluetooth::host::Prompt::Confirm(b.devices[1].addr, 482_913));
        assert_eq!(v.key(KEY_ESC, None, 0, &n), Effect::Bluetooth("confirm 5C:F3:70:11:22:33 no".into()));
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Bluetooth("confirm 5C:F3:70:11:22:33 yes".into()));
        v.bluetooth.as_mut().unwrap().prompt = None;
        // Forgetting the keyboard asks first; moving away forgets asking.
        v.key(KEY_UP, None, 0, &n);
        assert_eq!(v.key(KEY_DELETE, None, 0, &n), Effect::Redraw);
        assert!(v.status.starts_with("Press Enter again to forget Slate Keyboard"));
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Bluetooth("remove 00:1F:20:44:55:66".into()));
        assert_eq!(v.key(KEY_DELETE, None, 0, &n), Effect::Redraw);
        v.key(KEY_DOWN, None, 0, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Bluetooth("pair 5C:F3:70:11:22:33".into()));
        assert_eq!(v.key(0, Some('r'), 0, &n), Effect::Bluetooth("discover".into()));
        // Off: only the switch; no adapter or no service: nothing.
        v.bluetooth.as_mut().unwrap().state = "off".into();
        assert_eq!(v.rows(), 1);
        v.bluetooth.as_mut().unwrap().state = "none".into();
        assert_eq!(v.rows(), 0);
        v.bluetooth = None;
        assert_eq!(v.rows(), 0);
    }

    #[test]
    fn zone_lines() {
        let zones = b"Asia/Kolkata IST-5:30\nUTC UTC0\n";
        assert_eq!(zone_line("Asia/Kolkata", Some(zones), 0), "05:30 IST, UTC+05:30");
        assert_eq!(zone_line("UTC", Some(zones), 0), "00:00 UTC");
    }

    #[test]
    fn displays() {
        let n = names();
        let mut v = View::new(Settings::default(), "UTC");
        v.displays = crate::displays::Now::parse(
            "scale 1 auto\nDP-1 lit 0,0 1920x1080@144 primary modes 1920x1080@144 1920x1080@60\n\
             HDMI-A-1 lit 1920,0 1280x1024@60 modes 1280x1024@60\n",
        );
        section(&mut v, Section::Displays, &n);
        // Two displays and the scale.
        assert_eq!(v.rows(), 3);
        v.key(KEY_DOWN, None, 0, &n);
        assert_eq!(v.row, 1);
        v.key(KEY_ENTER, None, 0, &n);
        assert_eq!(v.page, Page::Display { name: "HDMI-A-1".into() });
        // Position: left of the primary.
        v.key(KEY_DOWN, None, 0, &n);
        v.key(KEY_DOWN, None, 0, &n);
        let e = v.key(KEY_ENTER, None, 0, &n);
        assert_eq!(
            e,
            Effect::Displays(
                "scale=auto\nDP-1 on 0,0 1920x1080@144 primary\nHDMI-A-1 on -1280,0 1280x1024@60\n".into()
            )
        );
        // Primary.
        v.key(KEY_DOWN, None, 0, &n);
        let e = v.key(KEY_ENTER, None, 0, &n);
        assert_eq!(
            e,
            Effect::Displays("scale=auto\nDP-1 on 1280,0 1920x1080@144\nHDMI-A-1 on 0,0 1280x1024@60 primary\n".into())
        );
        // Back on the main page, the scale: 1×.
        v.key(KEY_ESC, None, 0, &n);
        assert_eq!((v.page.clone(), v.row), (Page::Main, 1));
        v.key(KEY_DOWN, None, 0, &n);
        let e = v.key(KEY_ENTER, None, 0, &n);
        assert!(matches!(e, Effect::Displays(t) if t.starts_with("scale=1\n")));
        assert_eq!(v.displays.scale_words(), "1×");
    }

    #[test]
    fn graphics() {
        let n = names();
        let mut v = View::new(Settings::default(), "UTC");
        v.displays = crate::displays::Now::parse("scale 1 auto\nHDMI-A-1 lit 0,0 1920x1080@60 primary\n");
        v.graphics = Some(Graphics { installed: false, available: true, running: false, live: false });
        section(&mut v, Section::Displays, &n);
        // The display, the scale, then the Graphics row.
        assert_eq!(v.rows(), 3);
        v.key(KEY_DOWN, None, 0, &n);
        v.key(KEY_DOWN, None, 0, &n);
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Graphics(true));
        // The live system has no next start: the installer asks.
        v.graphics = Some(Graphics { installed: false, available: true, running: false, live: true });
        assert_eq!(v.key(KEY_ENTER, None, 0, &n), Effect::Redraw);
        assert!(v.status.contains("installer asks") && !v.status_bad);
        assert_eq!(v.graphics.unwrap().words(false), "chosen at install");
    }
}
