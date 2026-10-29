// SPDX-License-Identifier: MIT OR Apache-2.0

//! The graphical installer's screens and their behaviour (ADR 0034,
//! docs/design/INSTALLER_STYLE.md): Welcome (with the language: step 01), Region
//! (the time zone and the keyboard layout, ADR 0117), Disk
//! (and, for a disk that holds partitions, how to install on it and the
//! partitions, ADR 0116), Mode, Account, Install and Done, plus the quit
//! confirmation and the accessibility options. No platform code: a front end draws [`App`] on a
//! canvas, feeds it events, and carries out the [`Action`]s it returns
//! (the installation itself runs in the front end, which reports progress
//! with [`App::set_progress`]).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_ui::Canvas;
use slate_ui::anim::Transitions;
use slate_ui::edit::{Clip, LineEdit};
use slate_ui::icon::Icon;
use slate_ui::text::GlyphCache;
use slate_ui::theme::{Fonts, Theme};
use slate_ui::ui::{
    Area, CLOSE, Choice, Event, FOOTER_H, Field, Frame, Id, Key, Mods, TITLE_H, Ui, Variant, WINDOW_H, WINDOW_W,
    edit_key,
};

use crate::Placement;
use crate::engine::layout::MIN_ROOT;
use crate::engine::{DiskMap, ESP_BYTES, Row, SECTOR};
use crate::region::Countries;

/// The steps the sidebar lists (§4).
pub const STEPS: [&str; 8] = ["Language", "Region", "Disk", "Mode", "Desktop", "Network", "Account", "Install"];

/// Languages offered (only English exists yet: docs/GAPS.md), with the
/// locale, and the keyboard layout and time zone each suggests.
pub const LANGUAGES: [(&str, &str, &str, &str); 2] = [
    ("English (United States)", "en_US.UTF-8", "us", "America/New_York"),
    ("English (United Kingdom)", "en_GB.UTF-8", "gb", "Europe/London"),
];

/// The time zones whose names have `filter` in them (any case; a space
/// for an underscore), or that serve a country whose name has it or whose
/// code it is (ADR 0151). A country's whole name gives only its zones
/// ("India" is not Indiana).
pub fn zone_matches(names: &[String], countries: &Countries, filter: &str) -> Vec<usize> {
    if let Some(code) = countries.named(filter) {
        let own: Vec<usize> = (0..names.len()).filter(|&i| countries.serves(&names[i], code)).collect();
        if !own.is_empty() {
            return own;
        }
    }
    let words = filter.trim().to_ascii_lowercase();
    let f = words.replace(' ', "_");
    names
        .iter()
        .enumerate()
        .filter(|(_, n)| n.to_ascii_lowercase().contains(&f) || countries.matches(n, &words))
        .map(|(i, _)| i)
        .collect()
}

/// The keyboard layouts whose names or descriptions have `filter` in them.
pub fn layout_matches(filter: &str) -> Vec<usize> {
    let f = filter.trim().to_ascii_lowercase();
    slate_term::keymap::Layout::all()
        .enumerate()
        .filter(|(_, l)| l.description().to_ascii_lowercase().contains(&f) || l.name().contains(&f))
        .map(|(i, _)| i)
        .collect()
}

/// A zone's name as people read it: "America/New York".
pub fn zone_label(name: &str) -> String {
    name.replace('_', " ")
}

/// The rows a filtered list shows: up to `n` of `candidates` around the
/// position of `selected` in them.
fn window(candidates: &[usize], selected: usize, n: usize) -> &[usize] {
    let at = candidates.iter().position(|&c| c == selected).unwrap_or(0);
    let start = at.saturating_sub(2).min(candidates.len().saturating_sub(n));
    &candidates[start..(start + n).min(candidates.len())]
}

/// The rows of the Region step's lists.
const REGION_ROWS: usize = 6;

/// What the install shows as it runs (§5, "Install"), in the order it
/// does them: the payload's signature is checked before anything is
/// written (ADR 0034).
pub const STAGES: [&str; 4] = ["Verifying signatures", "Preparing disk", "Writing system image", "Finishing up"];

/// The stage and the fraction done for an install's progress.
pub fn stage_of(p: crate::Progress) -> (usize, f32) {
    use crate::engine::Step;
    match p {
        crate::Progress::Verifying => (0, 0.02),
        crate::Progress::Step(Step::Partition) => (1, 0.05),
        crate::Progress::Step(Step::BootPartition) => (1, 0.07),
        crate::Progress::Step(Step::FileSystem) => (1, 0.09),
        crate::Progress::Step(Step::Copy(done, total)) => (2, 0.10 + 0.80 * done as f32 / total.max(1) as f32),
        crate::Progress::Step(Step::Account) => (3, 0.92),
        crate::Progress::Step(Step::Finish) => (3, 0.95),
    }
}

/// A disk the installer can use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskChoice {
    /// The kernel name ("nvme0n1").
    pub name: String,
    /// What it is ("NVMe SSD").
    pub kind: String,
    pub bytes: u64,
    /// What it holds now (ADR 0116); None if it could not be read.
    pub map: Option<DiskMap>,
}

impl DiskChoice {
    /// Its partitions, if it has any.
    fn parts(&self) -> Option<&DiskMap> {
        self.map.as_ref().filter(|m| !m.parts.is_empty())
    }
}

/// How SlateOS goes on a disk that holds partitions (ADR 0116).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Way {
    Beside,
    Erase,
    Manual,
}

/// What a disk's name says it is.
pub fn disk_kind(name: &str, removable: bool) -> &'static str {
    if removable {
        "USB drive"
    } else if name.starts_with("nvme") {
        "NVMe SSD"
    } else if name.starts_with("vd") {
        "Virtual disk"
    } else {
        "SATA disk"
    }
}

/// A size as people read it: "1 TB", "500 GB", "1.5 TB" (decimal units,
/// as disks are sold).
pub fn human_size(bytes: u64) -> String {
    let units = [(1_000_000_000_000u64, "TB"), (1_000_000_000, "GB"), (1_000_000, "MB")];
    for (u, name) in units {
        if bytes >= u {
            let tenths = (bytes * 10 + u / 2) / u;
            return if tenths % 10 == 0 || tenths >= 1000 {
                format!("{} {name}", (tenths + 5) / 10)
            } else {
                format!("{}.{} {name}", tenths / 10, tenths % 10)
            };
        }
    }
    format!("{bytes} B")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Welcome,
    /// The time zone and the keyboard layout (ADR 0117).
    Region,
    Disk,
    /// How to install on a disk that holds partitions (ADR 0116).
    Way,
    /// Manual partitioning.
    Partitions,
    Mode,
    Desktop,
    /// Full graphics on a machine with an AMD card (ADR 0173), part of
    /// the Desktop step.
    Graphics,
    Network,
    Account,
    Install,
    Done,
}

/// What the front end should do after an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    None,
    /// Something changed: draw again.
    Redraw,
    /// Leave the installer for the live system ("Try SlateOS").
    Try,
    /// Leave the installer (the person confirmed quitting).
    Quit,
    /// Start installing with these answers.
    Install(alloc::boxed::Box<Answers>),
    /// Restart the computer (the Done screen).
    Restart,
}

/// Everything the person chose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answers {
    pub disk: String,
    pub encrypt: bool,
    pub linux_compat: bool,
    /// Install the Strata desktop (ADR 0037).
    pub desktop: bool,
    /// Full graphics: AMD's firmware from the medium (ADR 0173).
    pub full_graphics: bool,
    pub full_name: String,
    pub username: String,
    pub hostname: String,
    pub password: String,
    pub locale: &'static str,
    pub keyboard: &'static str,
    /// The time zone's name (ADR 0117).
    pub timezone: String,
    /// A fixed address for every card (ADR 0054); None: DHCP.
    pub network: Option<slate_netconf::Card>,
    /// The whole disk, or beside what it keeps (ADR 0116).
    pub placement: Placement,
}

// Control ids.
const LANGUAGE: Id = 1;
const LANGUAGE_OPTION: Id = 100;
const TRY: Id = 2;
const PRIMARY: Id = 3;
const BACK: Id = 4;
const ACCESSIBILITY: Id = 5;
const LARGE_TEXT: Id = 6;
const HIGH_CONTRAST: Id = 7;
const DISKS: Id = 10;
const DISK_ROW: Id = 200;
const ENCRYPT: Id = 11;
const MODES: Id = 12;
const MODE_ROW: Id = 300;
const DESKTOPS: Id = 13;
const DESKTOP_ROW: Id = 400;
const GRAPHICS: Id = 19;
const GRAPHICS_ROW: Id = 1000;
const NETWORKS: Id = 14;
const NETWORK_ROW: Id = 500;
const ADDRESS: Id = 25;
const GATEWAY: Id = 26;
const DNS: Id = 27;
const NAME: Id = 20;
const USERNAME: Id = 21;
const HOSTNAME: Id = 22;
const PASSWORD: Id = 23;
const CONFIRM: Id = 24;
const KEEP: Id = 30;
const QUIT: Id = 31;
const WAYS: Id = 15;
const WAY_ROW: Id = 600;
const PARTS: Id = 16;
const PART_ROW: Id = 700;
const ROOT_SIZE: Id = 28;
const DELETE_PART: Id = 32;
const UNDO_PARTS: Id = 33;
const ZONE_FILTER: Id = 35;
const KB_FILTER: Id = 36;
const ZONES: Id = 17;
const ZONE_ROW: Id = 800;
const KBS: Id = 18;
const KB_ROW: Id = 900;

/// The account fields' problems, by field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountErrors {
    pub name: Option<&'static str>,
    pub username: Option<&'static str>,
    pub hostname: Option<&'static str>,
    pub password: Option<&'static str>,
    pub confirm: Option<&'static str>,
}

impl AccountErrors {
    fn any(&self) -> bool {
        self.name.is_some()
            || self.username.is_some()
            || self.hostname.is_some()
            || self.password.is_some()
            || self.confirm.is_some()
    }
}

/// Check the account answers (user names as passwd(5) and useradd(8)
/// conventionally allow; host names per RFC 1123 labels).
pub fn validate_account(name: &str, user: &str, host: &str, pw: &str, confirm: &str) -> AccountErrors {
    let mut e = AccountErrors::default();
    if name.trim().is_empty() || name.contains(':') {
        e.name = Some("Enter your name.");
    }
    let ub = user.as_bytes();
    let user_ok = !ub.is_empty()
        && ub.len() <= 32
        && (ub[0].is_ascii_lowercase() || ub[0] == b'_')
        && ub.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
        && user != "root";
    if !user_ok {
        e.username = Some("Lowercase letters, digits, - and _, starting with a letter.");
    }
    let hb = host.as_bytes();
    let host_ok = !hb.is_empty()
        && hb.len() <= 63
        && hb[0] != b'-'
        && hb[hb.len() - 1] != b'-'
        && hb.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-');
    if !host_ok {
        e.hostname = Some("Letters, digits and -, up to 63.");
    }
    if pw.chars().count() < 6 {
        e.password = Some("Use at least 6 characters.");
    }
    if pw != confirm {
        e.confirm = Some("The passwords don't match.");
    }
    e
}

/// The Network step's problems, by field.
pub type NetworkErrors = slate_netconf::FieldErrors;

/// A fixed address for every card (`[*]`) from the Network step's fields
/// (ADR 0054), checked as Settings checks them.
pub fn network_card(address: &str, gateway: &str, dns: &str) -> Result<slate_netconf::Card, NetworkErrors> {
    slate_netconf::fixed("*", address, gateway, dns)
}

/// A username from a name: its first word, lowercased, letters and
/// digits only.
pub fn suggest_username(name: &str) -> String {
    let mut u: String = name
        .split_whitespace()
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    // It must start with a letter.
    while u.starts_with(|c: char| c.is_ascii_digit()) {
        u.remove(0);
    }
    u
}

/// A computer name from a username: `ada-slate`.
pub fn suggest_hostname(username: &str) -> String {
    if username.is_empty() { String::new() } else { format!("{username}-slate") }
}

/// Two presses on a field within this long (ms) are a double click.
const DOUBLE_CLICK_MS: i64 = 400;

pub struct App {
    pub screen: Screen,
    language: usize,
    language_open: bool,
    /// The Region step: the zones there are and the chosen one, the
    /// chosen layout (an index into `Layout::all`), their lists' filters,
    /// and whether the person chose (else they follow the language).
    zones: Vec<String>,
    zone: usize,
    zone_filter: String,
    countries: Countries,
    network_zone: Option<String>,
    kb: usize,
    kb_filter: String,
    region_chosen: bool,
    pub disks: Vec<DiskChoice>,
    disk: usize,
    encrypt: bool,
    linux_compat: bool,
    desktop: bool,
    full_graphics: bool,
    /// The Graphics step is asked: an AMD card the driver has and AMD's
    /// firmware on the medium (ADR 0173).
    pub graphics_offered: bool,
    /// The installer can go beside other systems: it started on UEFI
    /// firmware (boot entries can be made).
    pub uefi: bool,
    /// How to install on the chosen disk, when it holds partitions.
    way: Way,
    /// Manual partitioning: the partitions to delete, the selected row
    /// of the map after that, the root's size (GB) and what is wrong.
    deleted: Vec<u32>,
    part_row: usize,
    root_size: String,
    size_error: Option<String>,
    /// The Network step: a fixed address, its fields and their problems.
    fixed: bool,
    address: String,
    gateway: String,
    dns: String,
    net_errors: NetworkErrors,
    name: String,
    username: String,
    hostname: String,
    password: String,
    confirm: String,
    errors: AccountErrors,
    /// Whether the person has edited the username/host name (else they
    /// follow the name).
    username_edited: bool,
    hostname_edited: bool,
    stage: usize,
    fraction: f32,
    quitting: bool,
    accessibility_open: bool,
    pub large_text: bool,
    pub high_contrast: bool,
    /// Something went wrong installing (shown on the Install screen).
    pub failure: Option<String>,
    focus: Option<Id>,
    focus_visible: bool,
    pointer: Option<(f32, f32)>,
    frame: Frame,
    scale: f32,
    origin: (f32, f32),
    /// The focused text field's editor (ADR 0101): its caret and
    /// selection; the field's string follows its text.
    editing: Option<(Id, LineEdit)>,
    /// The field the pointer is selecting in (the button is down).
    dragging: Option<Id>,
    /// The time now (monotonic ms), which the front end sets before each
    /// event: two presses on a field soon after each other choose a word.
    pub now: i64,
    /// The last press on a field: which, where (device pixels), when.
    last_press: Option<(Id, f32, f32, i64)>,
    /// The installer's own clipboard (there is no desktop to share one
    /// with).
    clipboard: String,
    /// Colour changes easing over time; `now` is set before each frame.
    pub transitions: Transitions,
}

impl core::fmt::Debug for App {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "App({:?})", self.screen)
    }
}

impl App {
    pub fn new(disks: Vec<DiskChoice>) -> App {
        App {
            screen: Screen::Welcome,
            language: 0,
            language_open: false,
            zones: alloc::vec![String::from("UTC")],
            zone: 0,
            zone_filter: String::new(),
            countries: Countries::default(),
            network_zone: None,
            kb: 0,
            kb_filter: String::new(),
            region_chosen: false,
            disks,
            disk: 0,
            encrypt: true,
            linux_compat: false,
            desktop: true,
            full_graphics: false,
            graphics_offered: false,
            uefi: true,
            way: Way::Beside,
            deleted: Vec::new(),
            part_row: 0,
            root_size: String::new(),
            size_error: None,
            fixed: false,
            address: String::new(),
            gateway: String::new(),
            dns: String::new(),
            net_errors: NetworkErrors::default(),
            name: String::new(),
            username: String::new(),
            hostname: String::new(),
            password: String::new(),
            confirm: String::new(),
            errors: AccountErrors::default(),
            username_edited: false,
            hostname_edited: false,
            stage: 0,
            fraction: 0.0,
            quitting: false,
            accessibility_open: false,
            large_text: false,
            high_contrast: false,
            failure: None,
            focus: None,
            focus_visible: false,
            pointer: None,
            frame: Frame::default(),
            scale: 1.0,
            origin: (0.0, 0.0),
            editing: None,
            dragging: None,
            now: 0,
            last_press: None,
            clipboard: String::new(),
            transitions: Transitions::default(),
        }
    }

    /// A colour is still changing: draw again soon.
    pub fn animating(&self) -> bool {
        self.frame.animating
    }

    /// The disks on offer changed (one appeared late).
    pub fn set_disks(&mut self, disks: Vec<DiskChoice>) {
        self.disks = disks;
        self.disk = self.disk.min(self.disks.len().saturating_sub(1));
    }

    /// The keyboard layout chosen (the language's until the Region step).
    pub fn keyboard(&self) -> &'static str {
        slate_term::keymap::Layout::all().nth(self.kb).map_or("us", |l| l.name())
    }

    /// The countries each zone serves, and the zone a DHCP server named
    /// (ADR 0151), which comes before the language's.
    pub fn set_countries(&mut self, countries: Countries, network_zone: Option<String>) {
        self.countries = countries;
        self.network_zone = network_zone;
        self.follow_language();
    }

    /// The time zones there are (`slate_rt::tz::ZONES`' names).
    pub fn set_zones(&mut self, zones: Vec<String>) {
        if !zones.is_empty() {
            self.zones = zones;
        }
        self.follow_language();
    }

    /// The time zone chosen.
    pub fn timezone(&self) -> &str {
        self.zones.get(self.zone).map_or("UTC", String::as_str)
    }

    /// Until the person chooses, the zone and layout are the language's.
    fn follow_language(&mut self) {
        if self.region_chosen {
            return;
        }
        let (_, _, kb, zone) = LANGUAGES[self.language];
        self.kb = slate_term::keymap::Layout::all().position(|l| l.name() == kb).unwrap_or(0);
        let zone = crate::region::guess(self.network_zone.as_deref(), None, &self.countries, &self.zones)
            .unwrap_or_else(|| String::from(zone));
        self.zone = self.zones.iter().position(|z| *z == zone).unwrap_or(0);
    }

    /// The Region step's lists as filtered: zones and layouts.
    fn zone_candidates(&self) -> Vec<usize> {
        if self.zone_filter.trim().is_empty() {
            (0..self.zones.len()).collect()
        } else {
            zone_matches(&self.zones, &self.countries, &self.zone_filter)
        }
    }

    fn kb_candidates(&self) -> Vec<usize> {
        if self.kb_filter.trim().is_empty() {
            (0..slate_term::keymap::Layout::all().count()).collect()
        } else {
            layout_matches(&self.kb_filter)
        }
    }

    /// The install's progress: stage index into [`STAGES`] and the overall
    /// fraction done.
    pub fn set_progress(&mut self, stage: usize, fraction: f32) {
        self.stage = stage.min(STAGES.len() - 1);
        self.fraction = fraction;
    }

    /// The install finished.
    pub fn finished(&mut self) {
        self.screen = Screen::Done;
        self.focus = Some(PRIMARY);
    }

    /// Draw the current screen on `canvas` at `scale`.
    pub fn render(&mut self, canvas: &mut Canvas, cache: &mut GlyphCache, fonts: &Fonts<'_>, scale: f32) {
        // Larger text scales the whole window by a quarter, as far as the
        // screen allows.
        let scale = if self.large_text {
            let fit = (canvas.width as f32 / WINDOW_W).min(canvas.height as f32 / WINDOW_H);
            (scale * 1.25).min(fit).max(scale)
        } else {
            scale
        };
        let mut transitions = core::mem::take(&mut self.transitions);
        let mut ui = Ui::new(canvas, cache, fonts, scale);
        ui.anim = Some(&mut transitions);
        ui.theme = if self.high_contrast { Theme::HIGH_CONTRAST } else { Theme::LIGHT };
        ui.pointer = self.pointer.map(|(x, y)| ui.to_logical(x, y));
        ui.focus = self.focus;
        ui.focus_visible = self.focus_visible;
        ui.window("Install SlateOS");
        if self.quitting {
            self.draw_quit(&mut ui);
        } else {
            match self.screen {
                Screen::Welcome => self.draw_welcome(&mut ui),
                Screen::Region => self.draw_region(&mut ui),
                Screen::Disk => self.draw_disk(&mut ui),
                Screen::Way => self.draw_way(&mut ui),
                Screen::Partitions => self.draw_partitions(&mut ui),
                Screen::Mode => self.draw_mode(&mut ui),
                Screen::Desktop => self.draw_desktop(&mut ui),
                Screen::Graphics => self.draw_graphics(&mut ui),
                Screen::Network => self.draw_network(&mut ui),
                Screen::Account => self.draw_account(&mut ui),
                Screen::Install => self.draw_install(&mut ui),
                Screen::Done => self.draw_done(&mut ui),
            }
        }
        self.scale = ui.scale;
        self.origin = ui.origin;
        self.frame = core::mem::take(&mut ui.frame);
        drop(ui);
        self.transitions = transitions;
        // The tab order starts at the window's controls, but the close
        // button is reached last, as in desktop dialogs.
        if let Some(i) = self.frame.focus.iter().position(|&f| f == CLOSE) {
            let c = self.frame.focus.remove(i);
            self.frame.focus.push(c);
        }
    }

    // --- screens -------------------------------------------------------

    /// The footer's buttons, right-aligned: (id, label, variant) in visual
    /// order.
    fn footer(&self, ui: &mut Ui<'_, '_>, buttons: &[(Id, &str, Variant)]) {
        let y = WINDOW_H - FOOTER_H + (FOOTER_H - 40.0) / 2.0;
        let widths: Vec<f32> = buttons.iter().map(|&(_, l, v)| ui.button_width(l, v)).collect();
        let total: f32 = widths.iter().sum::<f32>() + 10.0 * (buttons.len().saturating_sub(1)) as f32;
        let mut x = WINDOW_W - 28.0 - total;
        for (&(id, label, v), w) in buttons.iter().zip(widths) {
            ui.button(id, Area::new(x, y, w, 40.0), label, v);
            x += w + 10.0;
        }
    }

    fn draw_welcome(&self, ui: &mut Ui<'_, '_>) {
        let line = "A secure, Linux-like system written from scratch in Rust. Stay locked down in Slate mode, or switch on Linux compatibility when you need it.";
        let lines = ui.wrap_lines(&ui.fonts.regular, 15.0, line, 440.0).len() as f32;
        let block = 56.0 + 28.0 + 41.4 + 8.0 + 22.5 * lines + 36.0 + 44.0;
        let space = WINDOW_H - TITLE_H - FOOTER_H;
        let mut y = TITLE_H + ((space - block) / 2.0).max(0.0);
        let cx = WINDOW_W / 2.0;
        ui.logo(cx - 28.0, y, 56.0);
        y += 56.0 + 28.0;
        y = ui.welcome_heading(cx, y, "Welcome to Slate", "OS") + 8.0;
        y = ui.supporting(cx - 220.0, y, 440.0, line, true) + 36.0;
        let dd = Area::new(cx - 150.0, y, 300.0, 44.0);
        ui.dropdown(LANGUAGE, dd, Icon::Globe, LANGUAGES[self.language].0);
        let a11y = Area::new(28.0, WINDOW_H - FOOTER_H + 14.0, 44.0, 44.0);
        ui.icon_button(ACCESSIBILITY, a11y, Icon::Accessibility);
        self.footer(ui, &[(TRY, "Try SlateOS", Variant::Secondary), (PRIMARY, "Install SlateOS", Variant::Primary)]);
        if self.language_open {
            let names: Vec<&str> = LANGUAGES.iter().map(|l| l.0).collect();
            ui.dropdown_list(LANGUAGE_OPTION, dd, &names, self.language);
        }
        if self.accessibility_open {
            self.draw_accessibility(ui, a11y);
        }
    }

    /// The accessibility options, in a panel above their button.
    fn draw_accessibility(&self, ui: &mut Ui<'_, '_>, anchor: Area) {
        let th = ui.theme;
        let panel = Area::new(anchor.x, anchor.y - 8.0 - 104.0, 220.0, 104.0);
        ui.fill(panel, 8.0, th.window);
        ui.border(panel, 8.0, 1.0, th.border);
        ui.checkbox(LARGE_TEXT, panel.x + 16.0, panel.y + 8.0, "Larger text", self.large_text);
        ui.checkbox(HIGH_CONTRAST, panel.x + 16.0, panel.y + 52.0, "High contrast", self.high_contrast);
    }

    /// The time zone and the keyboard layout (ADR 0117): two lists, each
    /// with a field that filters it. The layout applies at once, so the
    /// keyboard's field tries it out too.
    fn draw_region(&self, ui: &mut Ui<'_, '_>) {
        ui.sidebar(&STEPS, 1);
        let (x, w) = ui.content(true);
        let top = ui.heading(x, TITLE_H + 32.0, "Time zone and keyboard") + 24.0 + 23.0;
        let col = (w - 24.0) / 2.0;
        let layouts: Vec<slate_term::keymap::Layout> = slate_term::keymap::Layout::all().collect();
        let zone_rows: Vec<(String, Option<String>, usize)> = window(&self.zone_candidates(), self.zone, REGION_ROWS)
            .iter()
            .map(|&i| (zone_label(&self.zones[i]), self.countries.code(&self.zones[i]).map(String::from), i))
            .collect();
        let kb_rows: Vec<(String, Option<String>, usize)> = window(&self.kb_candidates(), self.kb, REGION_ROWS)
            .iter()
            .map(|&i| (String::from(layouts[i].description()), Some(String::from(layouts[i].name())), i))
            .collect();
        let lists = [
            (x, ZONE_FILTER, "Time zone", &self.zone_filter, ZONES, ZONE_ROW, &zone_rows, self.zone),
            (x + col + 24.0, KB_FILTER, "Keyboard", &self.kb_filter, KBS, KB_ROW, &kb_rows, self.kb),
        ];
        for (cx, field, label, value, group, row_id, rows, selected) in lists {
            let f = Field {
                label,
                value,
                cursor: self.cursor(field),
                mono: false,
                password: false,
                note: None,
                error: false,
            };
            ui.text_field(field, Area::new(cx, top, col, 44.0), &f);
            ui.tab_stop(group);
            let mut y = top + 44.0 + 12.0;
            if rows.is_empty() {
                ui.note(cx, y, "Nothing has that name.");
            }
            for (i, (title, value, item)) in rows.iter().enumerate() {
                let c = Choice { title, meta: None, value: value.as_deref(), description: &[] };
                ui.choice_row(row_id + i as Id, group, Area::new(cx, y, col, 36.0), &c, *item == selected);
                y += 36.0 + 6.0;
            }
        }
        self.footer(ui, &[(BACK, "Back", Variant::Secondary), (PRIMARY, "Continue", Variant::Primary)]);
    }

    fn draw_disk(&self, ui: &mut Ui<'_, '_>) {
        ui.sidebar(&STEPS, 2);
        let (x, w) = ui.content(true);
        let mut y = ui.heading(x, TITLE_H + 40.0, "Where should SlateOS be installed?") + 8.0;
        let text = "On a whole disk, or beside what a disk holds.";
        y = ui.supporting(x, y, w, text, false) + 28.0;
        ui.tab_stop(DISKS);
        if self.disks.is_empty() {
            y = ui.note(x, y, "No disk large enough was found (at least 2 GB).") + 20.0;
        }
        for (i, d) in self.disks.iter().enumerate() {
            let size = human_size(d.bytes);
            // What it holds, after its name.
            let meta = match d.parts() {
                Some(m) => {
                    let n = m.parts.len();
                    format!("{}  ·  {n} partition{}", d.name, if n == 1 { "" } else { "s" })
                }
                None => d.name.clone(),
            };
            let c = Choice { title: &d.kind, meta: Some(&meta), value: Some(&size), description: &[] };
            ui.choice_row(DISK_ROW + i as Id, DISKS, Area::new(x, y, w, 64.0), &c, i == self.disk);
            y += 64.0 + 8.0;
        }
        ui.checkbox(ENCRYPT, x, y - 8.0 + 20.0 - 14.0, "Encrypt disk", self.encrypt);
        let primary = if self.disks.is_empty() { Variant::Disabled } else { Variant::Primary };
        self.footer(ui, &[(BACK, "Back", Variant::Secondary), (PRIMARY, "Continue", primary)]);
    }

    /// The ways to install on the chosen disk that holds partitions, as
    /// far as they can be taken (ADR 0116).
    fn ways(&self) -> Vec<Way> {
        let Some(m) = self.disks.get(self.disk).and_then(DiskChoice::parts) else { return Vec::new() };
        let gpt = matches!(m.table, crate::engine::Table::Gpt(_));
        let mut v = Vec::new();
        if self.uefi && m.room_beside() {
            v.push(Way::Beside);
        }
        v.push(Way::Erase);
        if self.uefi && gpt {
            v.push(Way::Manual);
        }
        v
    }

    /// How to install on a disk that holds partitions (ADR 0116).
    fn draw_way(&self, ui: &mut Ui<'_, '_>) {
        ui.sidebar(&STEPS, 2);
        let (x, w) = ui.content(true);
        let d = &self.disks[self.disk];
        let Some(m) = d.parts() else { return };
        let mut y = ui.heading(x, TITLE_H + 40.0, "How should SlateOS be installed?") + 8.0;
        let others: Vec<String> = m.others(None).into_iter().map(|o| o.title).collect();
        let held = match others.as_slice() {
            [] => format!("{} has {} partitions on it.", d.name, m.parts.len()),
            [one] => format!("{} has {one} on it.", d.name),
            [rest @ .., last] => format!("{} has {} and {last} on it.", d.name, rest.join(", ")),
        };
        y = ui.supporting(x, y, w, &held, false) + 28.0;
        ui.tab_stop(WAYS);
        let free = human_size(m.largest_free().map_or(0, |f| f.1 * SECTOR));
        let text_w = w - 46.0 - 18.0 - 110.0;
        for (i, way) in self.ways().into_iter().enumerate() {
            let (title, desc, badge) = match way {
                Way::Beside => (
                    "Install beside it",
                    format!(
                        "In the free space ({free}). What is on the disk stays; choose the system when the computer starts."
                    ),
                    Some("recommended"),
                ),
                Way::Erase => ("Erase disk and install SlateOS", format!("Everything on {} is lost.", d.name), None),
                Way::Manual => (
                    "Choose partitions yourself",
                    String::from("Delete partitions, then choose where SlateOS goes and how much space it gets."),
                    None,
                ),
            };
            let desc = ui.wrap_lines(&ui.fonts.regular, 13.5, &desc, text_w);
            let lines: Vec<&str> = desc.iter().map(String::as_str).collect();
            let c = Choice { title, meta: None, value: badge, description: &lines };
            let h = Ui::choice_height(&c);
            ui.choice_row(WAY_ROW + i as Id, WAYS, Area::new(x, y, w, h), &c, way == self.way);
            y += h + 8.0;
        }
        let why = if !self.uefi {
            Some("Installing beside it needs UEFI: this computer started the installer in BIOS mode.")
        } else if !matches!(m.table, crate::engine::Table::Gpt(_)) {
            Some("SlateOS goes beside other systems only on GPT disks.")
        } else if !m.room_beside() {
            Some("There is not enough free space beside it: SlateOS needs 2.7 GB.")
        } else {
            None
        };
        if let Some(why) = why {
            ui.note(x, y + 12.0, why);
        }
        self.footer(ui, &[(BACK, "Back", Variant::Secondary), (PRIMARY, "Continue", Variant::Primary)]);
    }

    /// The chosen disk as manual partitioning leaves it.
    fn edited_map(&self) -> Option<DiskMap> {
        self.disks.get(self.disk).and_then(|d| d.map.as_ref()).map(|m| m.without(&self.deleted))
    }

    /// The root's size the field asks for (bytes; None: all of the free
    /// space), or what is wrong with it.
    fn chosen_size(&self, m: &DiskMap, free: (u64, u64)) -> Result<Option<u64>, String> {
        let t = self.root_size.trim().trim_end_matches("GB").trim();
        let size = match t {
            "" => None,
            t => match t.parse::<f64>() {
                Ok(gb) if gb > 0.0 => Some((gb * 1e9) as u64),
                _ => return Err(String::from("A size in GB, like 40.")),
            },
        };
        let esp = if m.shared_esp().is_some() { 0 } else { ESP_BYTES };
        let room = free.1 * SECTOR;
        if room < MIN_ROOT + esp {
            return Err(format!("Too small: SlateOS needs {}.", human_size(MIN_ROOT + esp)));
        }
        match size {
            Some(b) if b < MIN_ROOT => Err(format!("SlateOS needs at least {}.", human_size(MIN_ROOT))),
            Some(b) if b / (1 << 20) * (1 << 20) + esp > room => Err(String::from("That is more than the free space.")),
            _ => Ok(size),
        }
    }

    /// Manual partitioning (ADR 0116): the disk's partitions and free
    /// spaces on the left, what can be done with the selected one on the
    /// right.
    fn draw_partitions(&self, ui: &mut Ui<'_, '_>) {
        ui.sidebar(&STEPS, 2);
        let (x, w) = ui.content(true);
        let Some(m) = self.edited_map() else { return };
        let y0 = ui.heading(x, TITLE_H + 32.0, "Choose where SlateOS goes") + 24.0;
        let rows = m.rows();
        let lw = 330.0;
        ui.tab_stop(PARTS);
        let mut y = y0;
        for (i, row) in rows.iter().enumerate().take(PART_ROWS) {
            let (title, size) = match row {
                Row::Part(p) => (format!("{}  {}", p.number, shorten(&p.describe(), 24)), p.bytes()),
                Row::Free(_, n) => (String::from("Free space"), n * SECTOR),
            };
            let size = human_size(size);
            let c = Choice { title: &title, meta: None, value: Some(&size), description: &[] };
            ui.choice_row(PART_ROW + i as Id, PARTS, Area::new(x, y, lw, 36.0), &c, i == self.part_row);
            y += 36.0 + 6.0;
        }
        if rows.len() > PART_ROWS {
            ui.note(x, y, &format!("{} more not shown", rows.len() - PART_ROWS));
        }
        // What can be done with the selected row.
        let (px, pw) = (x + lw + 24.0, w - lw - 24.0);
        let disk = &self.disks[self.disk].name;
        let mut primary = Variant::Disabled;
        match rows.get(self.part_row) {
            Some(Row::Part(p)) => {
                let name = part_name(disk, p.number);
                let meta = format!("{name}  ·  {}", human_size(p.bytes()));
                let y = ui.detail(px, y0, &p.describe(), Some(&meta)) + 16.0;
                ui.button(DELETE_PART, Area::new(px, y, pw, 40.0), "Delete partition", Variant::Secondary);
                ui.note(px, y + 40.0 + 10.0, "Its files go when installing starts.");
            }
            Some(Row::Free(first, n)) => {
                let meta = human_size(n * SECTOR);
                let y = ui.detail(px, y0, "Free space", Some(&meta)) + 16.0 + 23.0;
                let err = self.size_error.clone().or_else(|| {
                    self.chosen_size(&m, (*first, *n)).err().filter(|_| {
                        // Only a space too small says so before anything is typed.
                        self.root_size.trim().is_empty()
                    })
                });
                let note = err.as_deref().or(Some("Empty: all of it."));
                let f = Field {
                    label: "Size for SlateOS (GB)",
                    value: &self.root_size,
                    cursor: self.cursor(ROOT_SIZE),
                    mono: true,
                    password: false,
                    note,
                    error: err.is_some(),
                };
                ui.text_field(ROOT_SIZE, Area::new(px, y, pw, 44.0), &f);
                if err.is_none() {
                    primary = Variant::Primary;
                }
            }
            None => {}
        }
        if !self.deleted.is_empty() {
            let gone: Vec<String> = self.deleted.iter().map(|n| format!("{n}")).collect();
            let top = WINDOW_H - FOOTER_H - 40.0 - 28.0 - 20.0;
            let what = if gone.len() == 1 { "Partition" } else { "Partitions" };
            ui.note(px, top, &format!("{what} {} deleted on installing.", gone.join(", ")));
            ui.button(UNDO_PARTS, Area::new(px, top + 24.0, pw, 40.0), "Undo deletions", Variant::Ghost);
        }
        self.footer(ui, &[(BACK, "Back", Variant::Secondary), (PRIMARY, "Continue", primary)]);
    }

    /// A step with two choices as rows (Mode, Desktop): `second` says
    /// whether the second row is chosen.
    #[allow(clippy::too_many_arguments)]
    fn two_choices(
        &self,
        ui: &mut Ui<'_, '_>,
        step: usize,
        (heading, supporting): (&str, &str),
        (group, first_row): (Id, Id),
        rows: [(&str, &str, Option<&str>); 2],
        second: bool,
        note: &str,
    ) {
        ui.sidebar(&STEPS, step);
        let (x, w) = ui.content(true);
        let mut y = ui.heading(x, TITLE_H + 40.0, heading) + 8.0;
        y = ui.supporting(x, y, w, supporting, false) + 28.0;
        ui.tab_stop(group);
        let text_w = w - 46.0 - 18.0 - 110.0;
        for (i, (title, desc, badge)) in rows.iter().enumerate() {
            let desc = ui.wrap_lines(&ui.fonts.regular, 13.5, desc, text_w);
            let lines: Vec<&str> = desc.iter().map(String::as_str).collect();
            let c = Choice { title, meta: None, value: *badge, description: &lines };
            let h = Ui::choice_height(&c);
            ui.choice_row(first_row + i as Id, group, Area::new(x, y, w, h), &c, (i == 1) == second);
            y += h + 8.0;
        }
        ui.note(x, y + 12.0, note);
        self.footer(ui, &[(BACK, "Back", Variant::Secondary), (PRIMARY, "Continue", Variant::Primary)]);
    }

    fn draw_mode(&self, ui: &mut Ui<'_, '_>) {
        let rows = [
            (
                "Slate mode",
                "The secure default. A signed, read-only system and per-app permissions.",
                Some("recommended"),
            ),
            (
                "Linux compatibility",
                "Adds an isolated Linux domain for programs that expect a traditional Linux environment.",
                None,
            ),
        ];
        let text = ("How should SlateOS run?", "Linux software runs either way.");
        self.two_choices(ui, 3, text, (MODES, MODE_ROW), rows, self.linux_compat, "You can switch modes later.");
    }

    /// The desktop: Strata, or the command line only (ADR 0037).
    fn draw_desktop(&self, ui: &mut Ui<'_, '_>) {
        let rows = [
            (
                "Strata desktop",
                "Windows, a panel, a terminal and a launcher, in Slate's graphite theme.",
                Some("recommended"),
            ),
            ("Command line only", "Log in on a text console. Nothing graphical is installed.", None),
        ];
        let text = ("How do you want to use SlateOS?", "Strata is SlateOS's own desktop.");
        let note = "Either way, the full command line is there.";
        self.two_choices(ui, 4, text, (DESKTOPS, DESKTOP_ROW), rows, !self.desktop, note);
    }

    /// Full graphics (ADR 0173): the notice, then SlateOS only (the
    /// default) or AMD's firmware.
    fn draw_graphics(&self, ui: &mut Ui<'_, '_>) {
        use slate_display::graphics;
        // One line each: the notice takes the room.
        let rows = [
            ("SlateOS only", "At the resolution your computer starts with.", None),
            ("Full graphics", "If it doesn't work, SlateOS goes back by itself.", None),
        ];
        let text = (graphics::TITLE, graphics::NOTICE);
        self.two_choices(ui, 4, text, (GRAPHICS, GRAPHICS_ROW), rows, self.full_graphics, "");
    }

    /// The network (ADR 0054): DHCP, or a fixed address with its gateway
    /// and name servers.
    fn draw_network(&self, ui: &mut Ui<'_, '_>) {
        ui.sidebar(&STEPS, 5);
        let (x, w) = ui.content(true);
        let mut y = ui.heading(x, TITLE_H + 40.0, "How should SlateOS connect?") + 8.0;
        y = ui.supporting(x, y, w, "Every network card gets these settings.", false) + 28.0;
        ui.tab_stop(NETWORKS);
        let rows = [
            (
                "Automatic (DHCP)",
                "The network gives SlateOS its address. Right for most networks.",
                Some("recommended"),
            ),
            ("Fixed address", "Give the address, gateway and name servers yourself.", None),
        ];
        let text_w = w - 46.0 - 18.0 - 110.0;
        for (i, (title, desc, badge)) in rows.iter().enumerate() {
            let desc = ui.wrap_lines(&ui.fonts.regular, 13.5, desc, text_w);
            let lines: Vec<&str> = desc.iter().map(String::as_str).collect();
            let c = Choice { title, meta: None, value: *badge, description: &lines };
            let h = Ui::choice_height(&c);
            ui.choice_row(NETWORK_ROW + i as Id, NETWORKS, Area::new(x, y, w, h), &c, (i == 1) == self.fixed);
            y += h + 8.0;
        }
        if self.fixed {
            // The three fields side by side.
            y += 20.0 + 23.0;
            let third = (w - 32.0) / 3.0;
            let e = &self.net_errors;
            let fields = [
                (ADDRESS, "Address", &self.address, e.address),
                (GATEWAY, "Gateway", &self.gateway, e.gateway),
                (DNS, "Name servers", &self.dns, e.dns),
            ];
            for (i, (id, label, value, err)) in fields.into_iter().enumerate() {
                let cursor = self.cursor(id);
                let f = Field { label, value, cursor, mono: true, password: false, note: err, error: err.is_some() };
                ui.text_field(id, Area::new(x + i as f32 * (third + 16.0), y, third, 44.0), &f);
            }
            y += 44.0 + 40.0;
        } else {
            y += 12.0;
        }
        ui.note(x, y, "You can change this later in Settings.");
        self.footer(ui, &[(BACK, "Back", Variant::Secondary), (PRIMARY, "Continue", Variant::Primary)]);
    }

    fn draw_account(&self, ui: &mut Ui<'_, '_>) {
        ui.sidebar(&STEPS, 6);
        let (x, w) = ui.content(true);
        let mut y = ui.heading(x, TITLE_H + 40.0, "Create your account") + 28.0 + 23.0;
        let half = (w - 16.0) / 2.0;
        let e = &self.errors;
        let field = |id, label, value, mono, password, err: Option<&'static str>| Field {
            label,
            value,
            cursor: self.cursor(id),
            mono,
            password,
            note: err,
            error: err.is_some(),
        };
        ui.text_field(NAME, Area::new(x, y, w, 44.0), &field(NAME, "Name", &self.name, false, false, e.name));
        y += 44.0 + 28.0 + 23.0;
        ui.text_field(
            USERNAME,
            Area::new(x, y, half, 44.0),
            &field(USERNAME, "Username", &self.username, true, false, e.username),
        );
        ui.text_field(
            HOSTNAME,
            Area::new(x + half + 16.0, y, half, 44.0),
            &field(HOSTNAME, "Computer name", &self.hostname, true, false, e.hostname),
        );
        y += 44.0 + 28.0 + 23.0;
        ui.text_field(
            PASSWORD,
            Area::new(x, y, half, 44.0),
            &field(PASSWORD, "Password", &self.password, false, true, e.password),
        );
        ui.text_field(
            CONFIRM,
            Area::new(x + half + 16.0, y, half, 44.0),
            &field(CONFIRM, "Confirm password", &self.confirm, false, true, e.confirm),
        );
        y += 44.0 + 28.0;
        if e.password.is_some() || e.confirm.is_some() {
            y += 12.0;
        }
        ui.note(x, y, "SlateOS has no root account. You'll approve system changes with this password.");
        self.footer(ui, &[(BACK, "Back", Variant::Secondary), (PRIMARY, "Install SlateOS", Variant::Primary)]);
    }

    fn draw_install(&self, ui: &mut Ui<'_, '_>) {
        ui.sidebar(&STEPS, 7);
        let (x, w) = ui.content(true);
        if let Some(f) = &self.failure {
            let y = ui.heading(x, TITLE_H + 40.0, "The installation failed") + 8.0;
            // The engine's message, as a sentence.
            let mut c = f.chars();
            let first = c.next().map(|c| c.to_uppercase().collect::<String>()).unwrap_or_default();
            let end = if f.ends_with('.') { "" } else { "." };
            let y = ui.supporting(x, y, w, &format!("{first}{}{end}", c.as_str()), false) + 20.0;
            let y = ui.note(x, y, "The disk was not installed completely.");
            ui.note(x, y, "Quit for a command line, where dmesg shows the kernel log.");
            self.footer(ui, &[(QUIT, "Quit", Variant::Primary)]);
            return;
        }
        let y = ui.heading(x, TITLE_H + 40.0, STAGES[self.stage]) + 28.0;
        ui.progress(x, y, w, self.fraction);
        ui.note(x, y + 26.0 + 4.0 + 20.0, "Don't turn off your computer.");
    }

    fn draw_done(&self, ui: &mut Ui<'_, '_>) {
        let block = 56.0 + 28.0 + 33.6 + 8.0 + 22.5 * 2.0;
        let mut y = TITLE_H + ((WINDOW_H - TITLE_H - FOOTER_H - block) / 2.0).max(0.0);
        let cx = WINDOW_W / 2.0;
        ui.logo(cx - 28.0, y, 56.0);
        y += 56.0 + 28.0;
        y = ui.heading_centred(cx, y, "SlateOS is ready") + 8.0;
        ui.supporting(
            cx - 220.0,
            y,
            440.0,
            "Restart to start using it. Remove the installation media when asked.",
            true,
        );
        self.footer(ui, &[(PRIMARY, "Restart now", Variant::Primary)]);
    }

    fn draw_quit(&self, ui: &mut Ui<'_, '_>) {
        let sidebar = !matches!(self.screen, Screen::Welcome | Screen::Done);
        if sidebar {
            ui.sidebar(&STEPS, self.step_index());
        }
        let (x, w) = ui.content(sidebar);
        let y = ui.heading(x, TITLE_H + 40.0, "Quit the installer?") + 8.0;
        ui.supporting(x, y, w, "Nothing on your disks has been changed.", false);
        self.footer(ui, &[(KEEP, "Keep installing", Variant::Secondary), (QUIT, "Quit", Variant::Primary)]);
    }

    fn step_index(&self) -> usize {
        match self.screen {
            Screen::Welcome => 0,
            Screen::Region => 1,
            Screen::Disk | Screen::Way | Screen::Partitions => 2,
            Screen::Mode => 3,
            Screen::Desktop | Screen::Graphics => 4,
            Screen::Network => 5,
            Screen::Account => 6,
            Screen::Install | Screen::Done => 7,
        }
    }

    // --- events --------------------------------------------------------

    /// Handle one event.
    pub fn handle(&mut self, ev: Event) -> Action {
        match ev {
            Event::PointerMove(x, y) => {
                self.pointer = Some((x, y));
                // Dragging in a field selects.
                if let Some(id) = self.dragging {
                    let lx = (x - self.origin.0) / self.scale;
                    if let Some(at) = self.frame.caret_at(id, lx)
                        && let Some(e) = self.editor()
                    {
                        e.place(at, true);
                    }
                }
                Action::Redraw
            }
            Event::PointerDown(x, y) => {
                self.pointer = Some((x, y));
                let (lx, ly) = ((x - self.origin.0) / self.scale, (y - self.origin.1) / self.scale);
                match self.frame.hit(lx, ly) {
                    Some(id) if self.is_text_field(id) => {
                        // The caret where the click is.
                        self.focus_visible = false;
                        self.focus = Some(id);
                        // A second press soon after the first, near it:
                        // the word there (ADR 0101's editor).
                        let (now, last) = (self.now, self.last_press.take());
                        let double = last.is_some_and(|(i, px, py, t)| {
                            i == id && now - t < DOUBLE_CLICK_MS && (px - x).abs() < 5.0 && (py - y).abs() < 5.0
                        });
                        if let Some(at) = self.frame.caret_at(id, lx)
                            && let Some(e) = self.editor()
                        {
                            if double { e.select_word(at) } else { e.place(at, false) }
                        }
                        self.last_press = if double { None } else { Some((id, x, y, now)) };
                        self.dragging = if double { None } else { Some(id) };
                        Action::Redraw
                    }
                    Some(id) => {
                        self.focus_visible = false;
                        self.click(id)
                    }
                    None => {
                        // A click elsewhere closes open lists.
                        let open = self.language_open || self.accessibility_open;
                        self.language_open = false;
                        self.accessibility_open = false;
                        if open { Action::Redraw } else { Action::None }
                    }
                }
            }
            Event::PointerUp(..) => {
                self.dragging = None;
                Action::None
            }
            Event::Key(k, m) => self.key(k, m),
        }
    }

    /// The caret and selection to show in field `id`, if it is being
    /// edited.
    fn cursor(&self, id: Id) -> Option<(usize, Option<usize>)> {
        self.editing.as_ref().filter(|(e, _)| *e == id).map(|(_, e)| (e.caret(), e.anchor()))
    }

    /// The focused field's editor, made from its text when the focus came
    /// to it.
    fn editor(&mut self) -> Option<&mut LineEdit> {
        let id = self.focus.filter(|&f| self.is_text_field(f))?;
        if self.editing.as_ref().is_none_or(|(e, _)| *e != id) {
            let value = self.field_text(id)?;
            let mut e = LineEdit::new(&value).with_max(64);
            e.secret = matches!(id, PASSWORD | CONFIRM);
            self.editing = Some((id, e));
        }
        self.editing.as_mut().map(|(_, e)| e)
    }

    /// Field `id`'s text, on the screen showing it.
    fn field_text(&self, id: Id) -> Option<String> {
        let s = match (self.screen, id) {
            (Screen::Network, ADDRESS) => &self.address,
            (Screen::Network, GATEWAY) => &self.gateway,
            (Screen::Network, DNS) => &self.dns,
            (Screen::Partitions, ROOT_SIZE) => &self.root_size,
            (Screen::Region, ZONE_FILTER) => &self.zone_filter,
            (Screen::Region, KB_FILTER) => &self.kb_filter,
            (Screen::Account, NAME) => &self.name,
            (Screen::Account, USERNAME) => &self.username,
            (Screen::Account, HOSTNAME) => &self.hostname,
            (Screen::Account, PASSWORD) => &self.password,
            (Screen::Account, CONFIRM) => &self.confirm,
            _ => return None,
        };
        Some(s.clone())
    }

    /// Edit the focused field: `f` changes its editor; the field takes its
    /// text (clearing its error), and the clipboard does what it asks.
    fn edit(&mut self, f: impl FnOnce(&mut LineEdit) -> slate_ui::edit::Outcome) -> Action {
        let Some(e) = self.editor() else { return Action::None };
        let mut out = f(e);
        if out.clip == Clip::Paste {
            let text = self.clipboard.clone();
            if let Some(e) = self.editor() {
                out.changed |= e.insert(&text);
            }
        }
        if let Clip::Copy(t) = &out.clip {
            self.clipboard = t.clone();
        }
        if out.changed {
            let text = self.editor().map(|e| e.text()).unwrap_or_default();
            if let Some(field) = self.field_mut() {
                *field = text;
            }
            self.after_edit();
        }
        if out.changed || out.moved { Action::Redraw } else { Action::None }
    }

    /// The control a click or Space/Enter activates.
    fn click(&mut self, id: Id) -> Action {
        if self.screen == Screen::Install && self.failure.is_none() {
            return Action::None;
        }
        match id {
            CLOSE => {
                if self.screen == Screen::Done {
                    return Action::Quit;
                }
                self.quitting = true;
                self.focus = Some(KEEP);
            }
            KEEP => self.quitting = false,
            QUIT => return Action::Quit,
            TRY => return Action::Try,
            LANGUAGE => {
                self.language_open = !self.language_open;
                self.focus = Some(LANGUAGE);
            }
            ACCESSIBILITY => self.accessibility_open = !self.accessibility_open,
            LARGE_TEXT => self.large_text = !self.large_text,
            HIGH_CONTRAST => self.high_contrast = !self.high_contrast,
            ENCRYPT => {
                self.encrypt = !self.encrypt;
                self.focus = Some(ENCRYPT);
            }
            BACK => self.go_back(),
            PRIMARY => return self.primary(),
            id if (LANGUAGE_OPTION..LANGUAGE_OPTION + LANGUAGES.len() as Id).contains(&id) => {
                self.language = (id - LANGUAGE_OPTION) as usize;
                self.language_open = false;
            }
            id if (DISK_ROW..DISK_ROW + self.disks.len() as Id).contains(&id) => {
                self.disk = (id - DISK_ROW) as usize;
                self.focus = Some(DISKS);
            }
            id if (WAY_ROW..WAY_ROW + self.ways().len() as Id).contains(&id) => {
                self.way = self.ways()[(id - WAY_ROW) as usize];
                self.focus = Some(WAYS);
            }
            id if (PART_ROW..PART_ROW + PART_ROWS as Id).contains(&id) => {
                self.part_row = (id - PART_ROW) as usize;
                self.size_error = None;
                self.focus = Some(PARTS);
            }
            id if (ZONE_ROW..ZONE_ROW + REGION_ROWS as Id).contains(&id) => {
                let c = self.zone_candidates();
                if let Some(&z) = window(&c, self.zone, REGION_ROWS).get((id - ZONE_ROW) as usize) {
                    self.zone = z;
                    self.region_chosen = true;
                }
                self.focus = Some(ZONES);
            }
            id if (KB_ROW..KB_ROW + REGION_ROWS as Id).contains(&id) => {
                let c = self.kb_candidates();
                if let Some(&k) = window(&c, self.kb, REGION_ROWS).get((id - KB_ROW) as usize) {
                    self.kb = k;
                    self.region_chosen = true;
                }
                self.focus = Some(KBS);
            }
            DELETE_PART => self.delete_part(),
            UNDO_PARTS => {
                self.deleted.clear();
                self.part_row = 0;
                self.size_error = None;
                self.focus = Some(PARTS);
            }
            id if id == MODE_ROW || id == MODE_ROW + 1 => {
                self.linux_compat = id == MODE_ROW + 1;
                self.focus = Some(MODES);
            }
            id if id == DESKTOP_ROW || id == DESKTOP_ROW + 1 => {
                self.desktop = id == DESKTOP_ROW;
                self.focus = Some(DESKTOPS);
            }
            id if id == GRAPHICS_ROW || id == GRAPHICS_ROW + 1 => {
                self.full_graphics = id == GRAPHICS_ROW + 1;
                self.focus = Some(GRAPHICS);
            }
            id if id == NETWORK_ROW || id == NETWORK_ROW + 1 => {
                self.fixed = id == NETWORK_ROW + 1;
                self.focus = Some(NETWORKS);
            }
            NAME | USERNAME | HOSTNAME | PASSWORD | CONFIRM | ADDRESS | GATEWAY | DNS | ROOT_SIZE | ZONE_FILTER
            | KB_FILTER => self.focus = Some(id),
            _ => return Action::None,
        }
        Action::Redraw
    }

    /// Delete the selected partition (manual partitioning): its space
    /// joins the free space around it, which is selected.
    fn delete_part(&mut self) {
        let Some(m) = self.edited_map() else { return };
        let Some(Row::Part(p)) = m.rows().get(self.part_row).copied() else { return };
        let first = p.first;
        self.deleted.push(p.number);
        if let Some(m) = self.edited_map() {
            self.part_row =
                m.rows().iter().position(|r| matches!(r, Row::Free(f, n) if (*f..f + n).contains(&first))).unwrap_or(0);
        }
        self.root_size.clear();
        self.size_error = None;
        self.editing = None;
        self.focus = Some(PARTS);
    }

    /// Where SlateOS goes, as the person chose.
    fn placement(&self) -> Placement {
        let has_parts = self.disks.get(self.disk).and_then(DiskChoice::parts).is_some();
        match self.way {
            _ if !has_parts => Placement::Whole,
            Way::Erase => Placement::Whole,
            Way::Beside => Placement::Beside { delete: Vec::new(), region: None, size: None },
            Way::Manual => {
                let m = self.edited_map();
                let free = m.as_ref().and_then(|m| match m.rows().get(self.part_row) {
                    Some(Row::Free(f, n)) => Some((*f, *n)),
                    _ => None,
                });
                let size = match (&m, free) {
                    (Some(m), Some(f)) => self.chosen_size(m, f).ok().flatten(),
                    _ => None,
                };
                Placement::Beside { delete: self.deleted.clone(), region: free.map(|f| f.0), size }
            }
        }
    }

    fn go_back(&mut self) {
        let has_parts = self.disks.get(self.disk).and_then(DiskChoice::parts).is_some();
        self.screen = match self.screen {
            Screen::Region => Screen::Welcome,
            Screen::Disk => Screen::Region,
            Screen::Way => Screen::Disk,
            Screen::Partitions => Screen::Way,
            Screen::Mode if has_parts && self.way == Way::Manual => Screen::Partitions,
            Screen::Mode if has_parts => Screen::Way,
            Screen::Mode => Screen::Disk,
            Screen::Desktop => Screen::Mode,
            Screen::Graphics => Screen::Desktop,
            Screen::Network if self.graphics_offered => Screen::Graphics,
            Screen::Network => Screen::Desktop,
            Screen::Account => Screen::Network,
            s => s,
        };
        self.focus = None;
    }

    /// The screen's primary action (Enter, or its primary button).
    fn primary(&mut self) -> Action {
        match self.screen {
            Screen::Welcome => {
                self.follow_language();
                self.screen = Screen::Region;
                self.focus = Some(ZONE_FILTER);
            }
            Screen::Region => {
                self.screen = Screen::Disk;
                self.focus = Some(DISKS);
            }
            Screen::Disk if !self.disks.is_empty() => {
                // A disk that holds partitions: how to install on it.
                self.deleted.clear();
                self.part_row = 0;
                self.root_size.clear();
                self.size_error = None;
                if let Some(&first) = self.ways().first()
                    && self.disks[self.disk].parts().is_some()
                {
                    self.way = first;
                    self.screen = Screen::Way;
                    self.focus = Some(WAYS);
                } else {
                    self.screen = Screen::Mode;
                    self.focus = Some(MODES);
                }
            }
            Screen::Way if self.way == Way::Manual => {
                self.screen = Screen::Partitions;
                // The largest free space, if there is one.
                if let Some(m) = self.edited_map() {
                    let largest = m.largest_free();
                    self.part_row = m
                        .rows()
                        .iter()
                        .position(|r| matches!(r, Row::Free(f, n) if Some((*f, *n)) == largest))
                        .unwrap_or(0);
                }
                self.focus = Some(PARTS);
            }
            Screen::Way => {
                self.screen = Screen::Mode;
                self.focus = Some(MODES);
            }
            Screen::Partitions => {
                let Some(m) = self.edited_map() else { return Action::None };
                let Some(&Row::Free(f, n)) = m.rows().get(self.part_row) else { return Action::None };
                if let Err(e) = self.chosen_size(&m, (f, n)) {
                    self.size_error = Some(e);
                    return Action::Redraw;
                }
                self.screen = Screen::Mode;
                self.focus = Some(MODES);
            }
            Screen::Mode => {
                self.screen = Screen::Desktop;
                self.focus = Some(DESKTOPS);
            }
            Screen::Desktop if self.graphics_offered => {
                self.screen = Screen::Graphics;
                self.focus = Some(GRAPHICS);
            }
            Screen::Desktop | Screen::Graphics => {
                self.screen = Screen::Network;
                self.focus = Some(NETWORKS);
            }
            Screen::Network => {
                if self.fixed {
                    match network_card(&self.address, &self.gateway, &self.dns) {
                        Ok(_) => self.net_errors = NetworkErrors::default(),
                        Err(e) => {
                            self.net_errors = e;
                            return Action::Redraw;
                        }
                    }
                }
                self.screen = Screen::Account;
                self.focus = Some(NAME);
            }
            Screen::Account => {
                self.errors =
                    validate_account(&self.name, &self.username, &self.hostname, &self.password, &self.confirm);
                if self.errors.any() {
                    return Action::Redraw;
                }
                self.screen = Screen::Install;
                self.focus = None;
                let (_, locale, _, _) = LANGUAGES[self.language];
                let keyboard = self.keyboard();
                return Action::Install(alloc::boxed::Box::new(Answers {
                    disk: self.disks[self.disk].name.clone(),
                    encrypt: self.encrypt,
                    linux_compat: self.linux_compat,
                    desktop: self.desktop,
                    full_graphics: self.graphics_offered && self.full_graphics,
                    full_name: String::from(self.name.trim()),
                    username: self.username.clone(),
                    hostname: self.hostname.clone(),
                    password: self.password.clone(),
                    locale,
                    keyboard,
                    network: if self.fixed { network_card(&self.address, &self.gateway, &self.dns).ok() } else { None },
                    placement: self.placement(),
                    timezone: String::from(self.timezone()),
                }));
            }
            Screen::Done => return Action::Restart,
            _ => return Action::None,
        }
        Action::Redraw
    }

    fn key(&mut self, k: Key, m: Mods) -> Action {
        if self.screen == Screen::Install && self.failure.is_none() {
            return Action::None;
        }
        // Text fields take their editing keys (ADR 0101).
        let in_field = self.focus.is_some_and(|f| self.is_text_field(f)) && !self.quitting;
        if in_field && let Some(ek) = edit_key(k, m) {
            self.focus_visible = true;
            return self.edit(|e| e.key(ek, m.shift, m.ctrl));
        }
        if m.ctrl && matches!(k, Key::Char(_)) {
            return Action::None;
        }
        match k {
            Key::Tab | Key::BackTab => {
                self.language_open = false;
                self.focus = self.frame.next_focus(self.focus, k == Key::BackTab);
                self.focus_visible = true;
                Action::Redraw
            }
            Key::Escape => {
                if self.language_open || self.accessibility_open {
                    self.language_open = false;
                    self.accessibility_open = false;
                } else if self.quitting {
                    self.quitting = false;
                } else if self.screen != Screen::Done {
                    self.quitting = true;
                    self.focus = Some(KEEP);
                }
                Action::Redraw
            }
            Key::Up | Key::Down | Key::Left | Key::Right => self.arrow(k),
            Key::Enter => {
                if self.language_open {
                    self.language_open = false;
                    return Action::Redraw;
                }
                match self.focus {
                    // A focused button does its own thing.
                    Some(
                        id @ (BACK | TRY | KEEP | QUIT | CLOSE | ACCESSIBILITY | LANGUAGE | DELETE_PART | UNDO_PARTS),
                    ) => self.click(id),
                    _ if self.quitting => {
                        self.quitting = false;
                        Action::Redraw
                    }
                    _ => self.primary(),
                }
            }
            Key::Space => match self.focus {
                Some(id)
                    if !self.is_text_field(id)
                        && !matches!(
                            id,
                            DISKS | MODES | DESKTOPS | GRAPHICS | NETWORKS | WAYS | PARTS | ZONES | KBS
                        ) =>
                {
                    self.click(id)
                }
                Some(id) if self.is_text_field(id) => self.type_char(' '),
                _ => Action::None,
            },
            // Delete on the partition list deletes the selected one.
            Key::Delete if self.focus == Some(PARTS) => self.click(DELETE_PART),
            Key::Home | Key::End | Key::Backspace | Key::Delete => Action::None,
            Key::Char(c) => self.type_char(c),
        }
    }

    /// Arrows move within radio groups and the open language list.
    fn arrow(&mut self, k: Key) -> Action {
        let forward = matches!(k, Key::Down | Key::Right);
        if self.language_open {
            self.language = step(self.language, LANGUAGES.len(), forward);
            return Action::Redraw;
        }
        match self.focus {
            Some(DISKS) if !self.disks.is_empty() => {
                self.disk = step(self.disk, self.disks.len(), forward);
                Action::Redraw
            }
            Some(DESKTOPS) => {
                self.desktop = !self.desktop;
                Action::Redraw
            }
            Some(ZONE_FILTER | ZONES) => {
                let c = self.zone_candidates();
                if let Some(at) = c.iter().position(|&z| z == self.zone).or((!c.is_empty()).then_some(0)) {
                    self.zone = c[step(at, c.len(), forward)];
                    self.region_chosen = true;
                }
                Action::Redraw
            }
            Some(KB_FILTER | KBS) => {
                let c = self.kb_candidates();
                if let Some(at) = c.iter().position(|&k| k == self.kb).or((!c.is_empty()).then_some(0)) {
                    self.kb = c[step(at, c.len(), forward)];
                    self.region_chosen = true;
                }
                Action::Redraw
            }
            Some(WAYS) => {
                let ways = self.ways();
                let i = ways.iter().position(|w| *w == self.way).unwrap_or(0);
                self.way = ways[step(i, ways.len(), forward)];
                Action::Redraw
            }
            Some(PARTS) => {
                let n = self.edited_map().map_or(0, |m| m.rows().len().min(PART_ROWS));
                if n > 0 {
                    self.part_row = step(self.part_row, n, forward);
                    self.size_error = None;
                }
                Action::Redraw
            }
            Some(MODES) => {
                self.linux_compat = !self.linux_compat;
                Action::Redraw
            }
            Some(GRAPHICS) => {
                self.full_graphics = !self.full_graphics;
                Action::Redraw
            }
            Some(NETWORKS) => {
                self.fixed = !self.fixed;
                Action::Redraw
            }
            Some(LANGUAGE) if matches!(k, Key::Down | Key::Up) => {
                self.language_open = true;
                Action::Redraw
            }
            _ => Action::None,
        }
    }

    fn is_text_field(&self, id: Id) -> bool {
        matches!(
            id,
            NAME | USERNAME
                | HOSTNAME
                | PASSWORD
                | CONFIRM
                | ADDRESS
                | GATEWAY
                | DNS
                | ROOT_SIZE
                | ZONE_FILTER
                | KB_FILTER
        )
    }

    /// The focused field, for editing (which clears its error).
    fn field_mut(&mut self) -> Option<&mut String> {
        if self.screen == Screen::Region {
            return match self.focus? {
                ZONE_FILTER => Some(&mut self.zone_filter),
                KB_FILTER => Some(&mut self.kb_filter),
                _ => None,
            };
        }
        if self.screen == Screen::Partitions && self.focus == Some(ROOT_SIZE) {
            self.size_error = None;
            return Some(&mut self.root_size);
        }
        if self.screen == Screen::Network {
            let e = &mut self.net_errors;
            return match self.focus? {
                ADDRESS => {
                    e.address = None;
                    Some(&mut self.address)
                }
                GATEWAY => {
                    e.gateway = None;
                    Some(&mut self.gateway)
                }
                DNS => {
                    e.dns = None;
                    Some(&mut self.dns)
                }
                _ => None,
            };
        }
        if self.screen != Screen::Account {
            return None;
        }
        let e = &mut self.errors;
        match self.focus? {
            NAME => {
                e.name = None;
                Some(&mut self.name)
            }
            USERNAME => {
                e.username = None;
                self.username_edited = true;
                Some(&mut self.username)
            }
            HOSTNAME => {
                e.hostname = None;
                self.hostname_edited = true;
                Some(&mut self.hostname)
            }
            PASSWORD => {
                e.password = None;
                e.confirm = None;
                Some(&mut self.password)
            }
            CONFIRM => {
                e.confirm = None;
                Some(&mut self.confirm)
            }
            _ => None,
        }
    }

    fn type_char(&mut self, c: char) -> Action {
        if c.is_control() || self.quitting {
            return Action::None;
        }
        let mut buf = [0u8; 4];
        let text: &str = c.encode_utf8(&mut buf);
        let text = String::from(text);
        self.edit(|e| {
            let changed = e.insert(&text);
            slate_ui::edit::Outcome { changed, moved: changed, clip: Clip::None }
        })
    }

    /// The username and computer name follow the name until edited; a
    /// filter picks the first that matches when the chosen one does not.
    fn after_edit(&mut self) {
        if self.screen == Screen::Region {
            let (c, chosen) = match self.focus {
                Some(ZONE_FILTER) => (self.zone_candidates(), &mut self.zone),
                Some(KB_FILTER) => (self.kb_candidates(), &mut self.kb),
                _ => return,
            };
            if !c.contains(chosen)
                && let Some(&first) = c.first()
            {
                *chosen = first;
            }
            self.region_chosen = true;
            return;
        }
        if self.focus == Some(NAME) {
            if self.editing.as_ref().is_some_and(|(id, _)| *id != NAME) {
                self.editing = None;
            }
            let user = suggest_username(&self.name);
            if !self.hostname_edited {
                self.hostname = suggest_hostname(&user);
            }
            if !self.username_edited {
                self.username = user;
            }
        }
    }
}

/// The rows the Partitions screen shows.
const PART_ROWS: usize = 8;

/// `s`, cut to `n` characters with an ellipsis.
fn shorten(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        String::from(s)
    } else {
        s.chars().take(n - 1).chain(core::iter::once('…')).collect()
    }
}

/// A partition's device name: `sda3`, `nvme0n1p3`.
pub fn part_name(disk: &str, n: u32) -> String {
    if disk.ends_with(|c: char| c.is_ascii_digit()) { format!("{disk}p{n}") } else { format!("{disk}{n}") }
}

fn step(i: usize, n: usize, forward: bool) -> usize {
    if forward { (i + 1).min(n - 1) } else { i.saturating_sub(1) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disks() -> Vec<DiskChoice> {
        alloc::vec![
            DiskChoice { name: "nvme0n1".into(), kind: "NVMe SSD".into(), bytes: 1_000_204_886_016, map: None },
            DiskChoice { name: "sda".into(), kind: "SATA disk".into(), bytes: 500_107_862_016, map: None },
        ]
    }

    /// A 1 TB disk as Windows leaves it, with 300 GB free after C:.
    fn windows_map() -> DiskMap {
        use crate::engine::Part;
        use crate::engine::layout::EspInfo;
        use slate_gpt::Guid;
        const G: u64 = 1_000_000_000 / 512;
        let msr = Guid::from_bytes(&[
            0x16, 0xe3, 0xc9, 0xe3, 0x5c, 0x0b, 0xb8, 0x4d, 0x81, 0x7d, 0xf9, 0x2d, 0xf0, 0x02, 0x15, 0xae,
        ]);
        let part = |number: u32, type_guid, first: u64, last: u64| Part {
            number,
            type_guid,
            guid: Guid::from_seed([number as u8; 16]),
            first,
            last,
            attributes: 0,
            name: String::new(),
            holds: None,
            esp: None,
        };
        let loaders =
            alloc::vec![(String::from("Windows Boot Manager"), String::from("EFI/Microsoft/Boot/bootmgfw.efi"))];
        let esp = Part {
            esp: Some(EspInfo { free: 70 << 20, slate: false, loaders }),
            ..part(1, Guid::EFI_SYSTEM, 2048, 206_847)
        };
        let ntfs = slate_fsprobe::Found { kind: slate_fsprobe::Kind::Ntfs, label: String::new(), uuid: String::new() };
        let c = Part { holds: Some(ntfs), ..part(3, Guid::BASIC_DATA, 239_616, 600 * G) };
        let parts = alloc::vec![esp, part(2, msr, 206_848, 239_615), c];
        DiskMap {
            bytes: 1_000_204_886_016,
            table: crate::engine::Table::Gpt(Guid::from_seed([9; 16])),
            parts,
            free: Vec::new(),
        }
        .without(&[])
    }

    fn zones() -> Vec<String> {
        ["UTC", "America/Chicago", "America/New_York", "Asia/Kolkata", "Europe/Berlin", "Europe/London", "Europe/Paris"]
            .map(String::from)
            .to_vec()
    }

    /// The Region step (ADR 0117): the language's zone and layout to
    /// start with; filters, arrows and clicks choose others; the layout
    /// is the keyboard's at once (the front end asks `keyboard()`).
    #[test]
    fn region() {
        let f = fonts();
        let mut cache = GlyphCache::new();
        let mut app = App::new(disks());
        app.set_zones(zones());
        app.set_countries(countries(), None);
        // UK English: London and the UK layout.
        app.language = 1;
        app.primary();
        assert_eq!((app.screen, app.focus), (Screen::Region, Some(ZONE_FILTER)));
        assert_eq!((app.timezone(), app.keyboard()), ("Europe/London", "gb"));
        draw(&mut app, &f, &mut cache, "region");
        // "new york" finds America/New_York; Down goes to the next match.
        typing(&mut app, "new york");
        assert_eq!(app.timezone(), "America/New_York");
        key(&mut app, Key::Backspace);
        for _ in 0..7 {
            key(&mut app, Key::Backspace);
        }
        typing(&mut app, "eur");
        assert_eq!(app.timezone(), "Europe/Berlin");
        key(&mut app, Key::Down);
        assert_eq!(app.timezone(), "Europe/London");
        // German, by filter, then Swiss German by the arrow.
        key(&mut app, Key::Tab);
        assert_eq!(app.focus, Some(ZONES));
        key(&mut app, Key::Tab);
        assert_eq!(app.focus, Some(KB_FILTER));
        typing(&mut app, "german");
        assert_eq!(app.keyboard(), "de");
        key(&mut app, Key::Down);
        assert_eq!(app.keyboard(), "ch");
        draw(&mut app, &f, &mut cache, "region-chosen");
        // A click on a row.
        let row = app.frame.hits.iter().find(|h| h.0 == KB_ROW).unwrap().1;
        let (ox, oy) = (210.0, 120.0);
        app.handle(Event::PointerDown(ox + row.x + 5.0, oy + row.y + 5.0));
        assert_eq!(app.keyboard(), "de");
        // Nothing matches: the choice stays.
        app.focus = Some(KB_FILTER);
        typing(&mut app, "zzz");
        assert!(app.kb_candidates().is_empty());
        assert_eq!(app.keyboard(), "de");
        draw(&mut app, &f, &mut cache, "region-none");
        // Choosing stops following the language.
        app.go_back();
        app.language = 0;
        app.primary();
        assert_eq!((app.timezone(), app.keyboard()), ("Europe/London", "de"));
        app.primary();
        assert_eq!(app.screen, Screen::Disk);
        assert_eq!(zone_matches(&zones(), &countries(), "KOL"), [3]);
        // Countries' names and codes find their zones (ADR 0151).
        assert_eq!(zone_matches(&zones(), &countries(), "norway"), [4]);
        assert_eq!(zone_matches(&zones(), &countries(), "united states"), [1, 2]);
        assert_eq!(zone_matches(&zones(), &countries(), "india"), [3]);
        assert_eq!(zone_matches(&zones(), &countries(), "Ind"), [3]);
        let more = [zones(), alloc::vec![String::from("America/Indiana/Knox")]].concat();
        assert_eq!(zone_matches(&more, &countries(), " India "), [3]);
        assert_eq!(zone_matches(&more, &countries(), "indi"), [3, 7]);
        assert_eq!(zone_matches(&zones(), &countries(), "fr"), [6]);
        assert_eq!(zone_label("America/New_York"), "America/New York");
    }

    fn countries() -> Countries {
        Countries::parse(
            "DE Germany\nGB United Kingdom\nIN India\nNO Norway\nUS United States\nFR France\n\
             America/New_York US\nAmerica/Chicago US\nAsia/Kolkata IN\nEurope/Berlin DE,NO\n\
             Europe/London GB\nEurope/Paris FR\n",
        )
    }

    /// A zone a DHCP server named comes before the language's, until the
    /// person chooses (ADR 0151).
    #[test]
    fn region_from_the_network() {
        let mut app = App::new(disks());
        app.set_zones(zones());
        app.set_countries(countries(), Some("Asia/Kolkata".into()));
        app.language = 1;
        app.primary();
        assert_eq!((app.timezone(), app.keyboard()), ("Asia/Kolkata", "gb"));
        // One the system doesn't know is passed over.
        let mut app = App::new(disks());
        app.set_zones(zones());
        app.set_countries(countries(), Some("Mars/Olympus".into()));
        assert_eq!(app.timezone(), "America/New_York");
    }

    fn windows_disks() -> Vec<DiskChoice> {
        alloc::vec![DiskChoice {
            name: "nvme0n1".into(),
            kind: "NVMe SSD".into(),
            bytes: 1_000_204_886_016,
            map: Some(windows_map()),
        }]
    }

    /// Beside Windows (ADR 0116): the way chosen, and manual partitioning
    /// with a partition deleted and a size typed.
    #[test]
    fn beside_and_manual() {
        let f = fonts();
        let mut cache = GlyphCache::new();
        let mut app = App::new(windows_disks());
        app.primary();
        app.primary();
        app.primary();
        assert_eq!(app.screen, Screen::Way);
        draw(&mut app, &f, &mut cache, "way");
        assert_eq!(app.ways(), [Way::Beside, Way::Erase, Way::Manual]);
        assert_eq!(app.placement(), Placement::Beside { delete: Vec::new(), region: None, size: None });
        key(&mut app, Key::Down);
        assert_eq!((app.way, app.placement()), (Way::Erase, Placement::Whole));
        key(&mut app, Key::Down);
        key(&mut app, Key::Enter);
        assert_eq!(app.screen, Screen::Partitions);
        draw(&mut app, &f, &mut cache, "partitions");
        // The free space after C: is selected; a size too small says so.
        assert_eq!(app.part_row, 3);
        key(&mut app, Key::Tab);
        assert_eq!(app.focus, Some(ROOT_SIZE));
        typing(&mut app, "1");
        assert_eq!(key(&mut app, Key::Enter), Action::Redraw);
        assert!(app.size_error.as_deref().unwrap().contains("at least"));
        draw(&mut app, &f, &mut cache, "partitions-error");
        key(&mut app, Key::Backspace);
        typing(&mut app, "120");
        // C: deleted: one free space from the reserved partition on.
        app.focus = Some(PARTS);
        key(&mut app, Key::Up);
        assert_eq!(app.part_row, 2);
        draw(&mut app, &f, &mut cache, "partitions-c");
        assert_eq!(key(&mut app, Key::Delete), Action::Redraw);
        assert_eq!(app.deleted, [3]);
        assert_eq!(app.part_row, 2);
        assert_eq!(app.root_size, "");
        draw(&mut app, &f, &mut cache, "partitions-deleted");
        app.focus = Some(ROOT_SIZE);
        typing(&mut app, "500");
        key(&mut app, Key::Enter);
        assert_eq!(app.screen, Screen::Mode);
        let free = app.edited_map().unwrap().free[0];
        assert_eq!(free.0, 239_616);
        let want = Placement::Beside { delete: alloc::vec![3], region: Some(free.0), size: Some(500_000_000_000) };
        assert_eq!(app.placement(), want);
        // Back comes to the partitions as they were left.
        app.go_back();
        assert_eq!((app.screen, app.deleted.as_slice()), (Screen::Partitions, &[3][..]));
        app.focus = Some(PARTS);
        key(&mut app, Key::Tab);
        key(&mut app, Key::Tab);
        assert_eq!(app.focus, Some(UNDO_PARTS));
        key(&mut app, Key::Enter);
        assert!(app.deleted.is_empty());
        // Without UEFI, beside is not offered, and the note says why.
        let mut bios = App::new(windows_disks());
        bios.uefi = false;
        bios.primary();
        bios.primary();
        bios.primary();
        assert_eq!((bios.screen, bios.ways()), (Screen::Way, alloc::vec![Way::Erase]));
        draw(&mut bios, &f, &mut cache, "way-bios");
    }

    fn fonts() -> Fonts<'static> {
        let read = |n: &str| -> &'static [u8] {
            let p = format!("{}/../../assets/fonts/{n}", env!("CARGO_MANIFEST_DIR"));
            alloc::boxed::Box::leak(std::fs::read(p).unwrap().into_boxed_slice())
        };
        Fonts::new([
            read("HostGrotesk-400.ttf"),
            read("HostGrotesk-500.ttf"),
            read("HostGrotesk-600.ttf"),
            read("HostGrotesk-800.ttf"),
            read("DMMono-Regular.ttf"),
        ])
        .unwrap()
    }

    fn draw(app: &mut App, f: &Fonts<'_>, cache: &mut GlyphCache, name: &str) -> Canvas {
        let mut c = Canvas::new(1280, 800, slate_ui::Color::rgb(0));
        app.render(&mut c, cache, f, 1.0);
        if let Ok(dir) = std::env::var("SLATE_UI_OUT") {
            std::fs::write(format!("{dir}/{name}.png"), slate_ui::png::encode(&c)).unwrap();
        }
        c
    }

    fn key(app: &mut App, k: Key) -> Action {
        app.handle(Event::Key(k, Mods::NONE))
    }

    fn key_with(app: &mut App, k: Key, shift: bool, ctrl: bool) -> Action {
        app.handle(Event::Key(k, Mods { shift, ctrl }))
    }

    fn typing(app: &mut App, s: &str) {
        for c in s.chars() {
            key(app, Key::Char(c));
        }
    }

    #[test]
    fn editing_text_fields() {
        let f = fonts();
        let mut cache = GlyphCache::new();
        let mut app = App::new(disks());
        app.screen = Screen::Account;
        app.focus = Some(NAME);
        // Typing at a caret moved home; the username follows the name.
        typing(&mut app, "Lovelace");
        key(&mut app, Key::Home);
        typing(&mut app, "Ada ");
        assert_eq!((app.name.as_str(), app.username.as_str()), ("Ada Lovelace", "ada"));
        // A word selected backwards and copied; pasted over the username.
        key(&mut app, Key::End);
        key_with(&mut app, Key::Left, true, true);
        key_with(&mut app, Key::Char('c'), false, true);
        assert_eq!(app.clipboard, "Lovelace");
        draw(&mut app, &f, &mut cache, "account-editing-name");
        key(&mut app, Key::Tab);
        assert_eq!(app.focus, Some(USERNAME));
        key_with(&mut app, Key::Char('a'), false, true);
        key_with(&mut app, Key::Char('v'), false, true);
        assert_eq!(app.username, "Lovelace");
        key_with(&mut app, Key::Backspace, false, true);
        assert_eq!(app.username, "");
        typing(&mut app, "ada");
        // Passwords copy nothing.
        app.focus = Some(PASSWORD);
        typing(&mut app, "secret");
        key_with(&mut app, Key::Char('a'), false, true);
        key_with(&mut app, Key::Char('c'), false, true);
        assert_eq!(app.clipboard, "Lovelace");
        // The pointer: a click puts the caret between characters, a drag
        // selects, typing replaces the selection.
        app.focus = Some(NAME);
        draw(&mut app, &f, &mut cache, "account-editing-before");
        let field = app.frame.fields.iter().find(|x| x.id == NAME).unwrap().clone();
        let area = app.frame.hits.iter().find(|h| h.0 == NAME).unwrap().1;
        let dev = |i: usize| {
            (app.origin.0 + (field.x + field.carets[i]) * app.scale, app.origin.1 + (area.y + 20.0) * app.scale)
        };
        let (x0, y0) = dev(4);
        let (x1, _) = dev(8);
        let (xw, yw) = dev(1);
        app.handle(Event::PointerDown(x0, y0));
        app.handle(Event::PointerMove(x1, y0));
        app.handle(Event::PointerUp(x1, y0));
        assert_eq!(app.cursor(NAME), Some((8, Some(4))));
        draw(&mut app, &f, &mut cache, "account-editing");
        typing(&mut app, "King");
        assert_eq!(app.name, "Ada Kinglace");
        // Delete, and shift + Home.
        key(&mut app, Key::Delete);
        key_with(&mut app, Key::Home, true, false);
        assert_eq!(app.cursor(NAME), Some((0, Some(8))));
        assert_eq!(app.name, "Ada Kingace");
        // Two presses soon after each other choose the word; slow ones
        // only place the caret.
        let (x, y) = (xw, yw);
        app.now = 10_000;
        app.handle(Event::PointerDown(x, y));
        app.handle(Event::PointerUp(x, y));
        app.now = 10_250;
        app.handle(Event::PointerDown(x, y));
        app.handle(Event::PointerUp(x, y));
        let (c, a) = app.cursor(NAME).unwrap();
        assert_eq!((c.min(a.unwrap()), c.max(a.unwrap())), (0, 3), "Ada");
        app.now = 20_000;
        app.handle(Event::PointerDown(x, y));
        app.now = 21_000;
        app.handle(Event::PointerDown(x, y));
        assert_eq!(app.cursor(NAME), Some((1, None)));
    }

    /// The Graphics step (ADR 0173): only when offered, SlateOS only
    /// first, and full graphics in the answers when chosen.
    #[test]
    fn graphics_step() {
        let mut app = App::new(disks());
        app.screen = Screen::Desktop;
        app.primary();
        assert_eq!(app.screen, Screen::Network, "not offered: not asked");
        app.go_back();
        app.graphics_offered = true;
        app.primary();
        assert_eq!((app.screen, app.focus, app.full_graphics), (Screen::Graphics, Some(GRAPHICS), false));
        assert_eq!(app.step_index(), 4);
        key(&mut app, Key::Down);
        assert!(app.full_graphics);
        app.primary();
        assert_eq!(app.screen, Screen::Network);
        app.go_back();
        assert_eq!(app.screen, Screen::Graphics);
        app.go_back();
        assert_eq!(app.screen, Screen::Desktop);
        // Chosen, then no longer offered (it can't be): not in the answers.
        app.screen = Screen::Account;
        app.name = "Ada Lovelace".into();
        app.username = "ada".into();
        app.hostname = "ada-slate".into();
        app.password = "secret1".into();
        app.confirm = "secret1".into();
        let Action::Install(a) = app.primary() else { panic!("no install") };
        assert!(a.full_graphics);
        app.graphics_offered = false;
        app.screen = Screen::Account;
        let Action::Install(a) = app.primary() else { panic!("no install") };
        assert!(!a.full_graphics);
    }

    #[test]
    fn sizes_and_kinds() {
        assert_eq!(human_size(1_000_204_886_016), "1 TB");
        assert_eq!(human_size(500_107_862_016), "500 GB");
        assert_eq!(human_size(1_500_000_000_000), "1.5 TB");
        assert_eq!(human_size(256_060_514_304), "256 GB");
        assert_eq!(human_size(64_023_257_088), "64 GB");
        assert_eq!(human_size(7_864_320_000), "7.9 GB");
        assert_eq!(disk_kind("nvme0n1", false), "NVMe SSD");
        assert_eq!(disk_kind("sdb", true), "USB drive");
    }

    #[test]
    fn validation() {
        let ok = validate_account("Ada Lovelace", "ada", "ada-slate", "secret1", "secret1");
        assert!(!ok.any());
        let bad = validate_account("", "Ada", "-x", "abc", "abd");
        assert!(bad.name.is_some() && bad.username.is_some() && bad.hostname.is_some());
        assert!(bad.password.is_some() && bad.confirm.is_some());
        assert!(validate_account("A", "root", "h", "secret1", "secret1").username.is_some());
    }

    /// The whole flow by keyboard, rendering every screen on the way.
    #[test]
    fn keyboard_flow() {
        let f = fonts();
        let mut cache = GlyphCache::new();
        let mut app = App::new(disks());
        let welcome = draw(&mut app, &f, &mut cache, "welcome");
        // The window surface is where it should be, centred.
        assert_eq!(welcome.pixel(640, 400) | 0xFF00_0000, 0xFFF3_F2F2);
        assert_eq!(key(&mut app, Key::Enter), Action::Redraw);
        assert_eq!(app.screen, Screen::Region);
        assert_eq!((app.timezone(), app.keyboard()), ("UTC", "us"));
        key(&mut app, Key::Enter);
        assert_eq!(app.screen, Screen::Disk);
        draw(&mut app, &f, &mut cache, "disk");
        key(&mut app, Key::Down);
        assert_eq!(app.disk, 1);
        key(&mut app, Key::Up);
        key(&mut app, Key::Enter);
        assert_eq!(app.screen, Screen::Mode);
        draw(&mut app, &f, &mut cache, "mode");
        key(&mut app, Key::Down);
        assert!(app.linux_compat);
        key(&mut app, Key::Up);
        key(&mut app, Key::Enter);
        assert_eq!(app.screen, Screen::Desktop);
        draw(&mut app, &f, &mut cache, "desktop");
        key(&mut app, Key::Down);
        assert!(!app.desktop);
        key(&mut app, Key::Up);
        key(&mut app, Key::Enter);
        assert_eq!(app.screen, Screen::Network);
        draw(&mut app, &f, &mut cache, "network");
        // A fixed address: bad fields stop it, good ones pass.
        key(&mut app, Key::Down);
        assert!(app.fixed);
        draw(&mut app, &f, &mut cache, "network-fixed-empty");
        key(&mut app, Key::Tab);
        assert_eq!(app.focus, Some(ADDRESS));
        typing(&mut app, "192.168.1.20");
        key(&mut app, Key::Tab);
        typing(&mut app, "192.168.1");
        assert_eq!(key(&mut app, Key::Enter), Action::Redraw);
        draw(&mut app, &f, &mut cache, "network-fixed-error");
        assert_eq!(app.screen, Screen::Network);
        assert!(app.net_errors.address.is_some() && app.net_errors.gateway.is_some() && app.net_errors.dns.is_none());
        key(&mut app, Key::BackTab);
        typing(&mut app, "/24");
        assert_eq!(app.net_errors.address, None, "editing clears the field's error");
        key(&mut app, Key::Tab);
        typing(&mut app, ".1");
        key(&mut app, Key::Tab);
        typing(&mut app, "9.9.9.9 1.1.1.1");
        key(&mut app, Key::Enter);
        assert_eq!(app.screen, Screen::Account);
        key(&mut app, Key::Escape);
        key(&mut app, Key::Escape);
        app.go_back();
        assert_eq!(app.screen, Screen::Network);
        assert_eq!(app.address, "192.168.1.20/24", "going back keeps the answers");
        app.primary();
        assert_eq!(app.screen, Screen::Account);
        typing(&mut app, "Ada Lovelace");
        assert_eq!((app.username.as_str(), app.hostname.as_str()), ("ada", "ada-slate"));
        // Missing passwords: errors, no install.
        assert_eq!(key(&mut app, Key::Enter), Action::Redraw);
        draw(&mut app, &f, &mut cache, "account-errors");
        assert_eq!(app.screen, Screen::Account);
        draw(&mut app, &f, &mut cache, "account");
        for _ in 0..3 {
            key(&mut app, Key::Tab);
        }
        assert_eq!(app.focus, Some(PASSWORD));
        typing(&mut app, "secret1");
        assert_eq!(app.errors.password, None, "editing clears the field's error");
        key(&mut app, Key::Tab);
        typing(&mut app, "secret1");
        draw(&mut app, &f, &mut cache, "account-filled");
        let a = key(&mut app, Key::Enter);
        let Action::Install(ans) = a else { panic!("{a:?}") };
        assert_eq!(ans.disk, "nvme0n1");
        assert!(ans.encrypt && !ans.linux_compat && ans.desktop);
        assert_eq!((ans.username.as_str(), ans.keyboard, ans.locale), ("ada", "us", "en_US.UTF-8"));
        let card = ans.network.expect("a fixed address");
        assert_eq!(card.words().join(" "), "* static 192.168.1.20/24 gateway 192.168.1.1 dns 9.9.9.9 1.1.1.1");
        app.set_progress(2, 0.42);
        assert_eq!(app.keyboard(), "us");
        draw(&mut app, &f, &mut cache, "install");
        // No way out while installing.
        assert_eq!(key(&mut app, Key::Escape), Action::None);
        app.finished();
        draw(&mut app, &f, &mut cache, "done");
        assert_eq!(key(&mut app, Key::Enter), Action::Restart);
    }

    #[test]
    fn quitting_asks_first() {
        let f = fonts();
        let mut cache = GlyphCache::new();
        let mut app = App::new(disks());
        draw(&mut app, &f, &mut cache, "welcome");
        key(&mut app, Key::Escape);
        draw(&mut app, &f, &mut cache, "quit");
        assert_eq!(key(&mut app, Key::Enter), Action::Redraw, "Enter keeps installing");
        key(&mut app, Key::Escape);
        draw(&mut app, &f, &mut cache, "quit");
        key(&mut app, Key::Tab);
        assert_eq!(key(&mut app, Key::Enter), Action::Quit);
    }

    #[test]
    fn pointer_selects_and_opens() {
        let f = fonts();
        let mut cache = GlyphCache::new();
        let mut app = App::new(disks());
        draw(&mut app, &f, &mut cache, "welcome");
        // The window is centred on the 1280 × 800 canvas at scale 1.
        let (ox, oy) = (210.0, 120.0);
        let lang = app.frame.hits.iter().find(|h| h.0 == LANGUAGE).unwrap().1;
        app.handle(Event::PointerDown(ox + lang.x + 10.0, oy + lang.y + 10.0));
        assert!(app.language_open);
        draw(&mut app, &f, &mut cache, "welcome-language");
        let second = app.frame.hits.iter().find(|h| h.0 == LANGUAGE_OPTION + 1).unwrap().1;
        app.handle(Event::PointerDown(ox + second.x + 5.0, oy + second.y + 5.0));
        assert_eq!((app.language, app.language_open), (1, false));
        let a11y = app.frame.hits.iter().find(|h| h.0 == ACCESSIBILITY).unwrap().1;
        app.handle(Event::PointerDown(ox + a11y.x + 5.0, oy + a11y.y + 5.0));
        draw(&mut app, &f, &mut cache, "welcome-accessibility");
        let hc = app.frame.hits.iter().find(|h| h.0 == HIGH_CONTRAST).unwrap().1;
        app.handle(Event::PointerDown(ox + hc.x + 5.0, oy + hc.y + 5.0));
        assert!(app.high_contrast);
        let large = app.frame.hits.iter().find(|h| h.0 == LARGE_TEXT).unwrap().1;
        app.handle(Event::PointerDown(ox + large.x + 5.0, oy + large.y + 5.0));
        assert!(app.large_text);
        let c = draw(&mut app, &f, &mut cache, "welcome-large-contrast");
        // 860 × 560 at 1.25 is 1075 × 700, centred: the left edge moves
        // from 210 to 102.
        assert_eq!(app.scale, 1.25);
        assert_eq!(c.pixel(110, 400) | 0xFF00_0000, 0xFFF3_F2F2);
    }

    /// FNV-1a over the pixels: a screen's fingerprint.
    fn fingerprint(c: &Canvas) -> u64 {
        c.pixels
            .iter()
            .flat_map(|p| p.to_le_bytes())
            .fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3))
    }

    /// Every screen in the states worth seeing, by name.
    fn screens(f: &Fonts<'_>) -> Vec<(&'static str, Canvas)> {
        let mut cache = GlyphCache::new();
        let mut out = Vec::new();
        let mut app = App::new(disks());
        let mut shot = |app: &mut App, name: &'static str, out: &mut Vec<(&'static str, Canvas)>| {
            out.push((name, draw(app, f, &mut cache, name)));
        };
        shot(&mut app, "welcome", &mut out);
        key(&mut app, Key::Tab);
        key(&mut app, Key::Down);
        shot(&mut app, "welcome-language", &mut out);
        key(&mut app, Key::Down);
        key(&mut app, Key::Enter);
        app.accessibility_open = true;
        shot(&mut app, "welcome-accessibility", &mut out);
        app.accessibility_open = false;
        key(&mut app, Key::Escape);
        shot(&mut app, "quit", &mut out);
        key(&mut app, Key::Escape);
        app.set_zones(zones());
        app.set_countries(countries(), None);
        app.primary();
        shot(&mut app, "region", &mut out);
        typing(&mut app, "ber");
        key(&mut app, Key::Tab);
        key(&mut app, Key::Tab);
        typing(&mut app, "ger");
        shot(&mut app, "region-filtered", &mut out);
        app.primary();
        shot(&mut app, "disk", &mut out);
        app.primary();
        key(&mut app, Key::Down);
        shot(&mut app, "mode-linux", &mut out);
        app.primary();
        shot(&mut app, "desktop", &mut out);
        // An AMD card and its firmware on the medium (ADR 0173).
        app.graphics_offered = true;
        app.primary();
        shot(&mut app, "graphics", &mut out);
        key(&mut app, Key::Down);
        shot(&mut app, "graphics-full", &mut out);
        key(&mut app, Key::Up);
        app.primary();
        shot(&mut app, "network", &mut out);
        key(&mut app, Key::Down);
        shot(&mut app, "network-fixed-empty", &mut out);
        key(&mut app, Key::Tab);
        typing(&mut app, "192.168.1.20");
        key(&mut app, Key::Tab);
        typing(&mut app, "192.168.1.1");
        app.primary();
        shot(&mut app, "network-fixed-error", &mut out);
        key(&mut app, Key::BackTab);
        typing(&mut app, "/24");
        key(&mut app, Key::Tab);
        key(&mut app, Key::Tab);
        typing(&mut app, "192.168.1.1 9.9.9.9");
        shot(&mut app, "network-fixed", &mut out);
        app.primary();
        typing(&mut app, "Ada Lovelace");
        app.primary();
        shot(&mut app, "account-errors", &mut out);
        for _ in 0..3 {
            key(&mut app, Key::Tab);
        }
        typing(&mut app, "secret1");
        key(&mut app, Key::Tab);
        typing(&mut app, "secret1");
        shot(&mut app, "account-filled", &mut out);
        // A selection in the name, by inversion (ADR 0101).
        app.focus = Some(NAME);
        key(&mut app, Key::End);
        key_with(&mut app, Key::Left, true, true);
        shot(&mut app, "account-selection", &mut out);
        app.primary();
        app.set_progress(2, 0.42);
        shot(&mut app, "install", &mut out);
        app.failure = Some("writing the disk: I/O error".into());
        shot(&mut app, "install-failed", &mut out);
        app.failure = None;
        app.finished();
        shot(&mut app, "done", &mut out);
        let mut app = App::new(Vec::new());
        app.primary();
        app.primary();
        shot(&mut app, "disk-none", &mut out);
        // Beside Windows (ADR 0116).
        let mut app = App::new(windows_disks());
        app.primary();
        app.primary();
        shot(&mut app, "disk-windows", &mut out);
        app.primary();
        shot(&mut app, "way", &mut out);
        key(&mut app, Key::Up);
        app.way = Way::Manual;
        app.primary();
        shot(&mut app, "partitions", &mut out);
        key(&mut app, Key::Up);
        shot(&mut app, "partitions-c", &mut out);
        key(&mut app, Key::Delete);
        shot(&mut app, "partitions-deleted", &mut out);
        app.focus = Some(ROOT_SIZE);
        typing(&mut app, "1");
        app.primary();
        shot(&mut app, "partitions-error", &mut out);
        let mut app = App::new(windows_disks());
        app.uefi = false;
        app.primary();
        app.primary();
        app.primary();
        shot(&mut app, "way-bios", &mut out);
        let mut app = App::new(disks());
        app.large_text = true;
        app.high_contrast = true;
        shot(&mut app, "welcome-large-contrast", &mut out);
        out
    }

    /// The screens look as they did when last reviewed: their fingerprints
    /// are in tests/screens.txt. After an intended change, look at them
    /// (`SLATE_UI_OUT=DIR` saves PNGs) and record them with
    /// `SLATE_UI_BLESS=1`.
    #[test]
    fn screens_match_references() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/screens.txt");
        let got: String = screens(&fonts()).iter().map(|(n, c)| format!("{n} {:016x}\n", fingerprint(c))).collect();
        if std::env::var_os("SLATE_UI_BLESS").is_some() {
            std::fs::write(path, &got).unwrap();
            return;
        }
        let want = std::fs::read_to_string(path).unwrap_or_default();
        let changed: Vec<&str> =
            got.lines().filter(|l| !want.lines().any(|w| w == *l)).map(|l| l.split(' ').next().unwrap_or(l)).collect();
        assert!(
            changed.is_empty() && got.lines().count() == want.lines().count(),
            "screens changed: {changed:?}; look at them (SLATE_UI_OUT=DIR) and record them with SLATE_UI_BLESS=1"
        );
    }
}
