// SPDX-License-Identifier: MIT OR Apache-2.0

//! `strata`: the session on KMS and evdev (ADR 0037). It takes the
//! screen, reads every input device, serves its apps (`server`), keeps the
//! window manager's state and draws the desktop when something changes
//! (and when the clock or the network changes). super + space opens the
//! launcher, the top bar's Applications button the Applications menu
//! and its power button the power dialog (ADR 0110); system actions go
//! through the approval dialog, which also answers the broker for other
//! programs (`agent`). A user who is not root
//! gets the screen and input devices from seatd.
//!
//! Leaving: super + shift + e exits with status 2 (back to the console's
//! shell), the launcher's "Log out" with 0 (the login session ends; see
//! /etc/profile).

use alloc::string::String;
use alloc::vec::Vec;

use slate_display::input::{Input, Inputs};
use slate_display::kms::screens::Screens;
use slate_display::seat::Seat;
use slate_rt::{fs, lossy, process};
use slate_ui::paint::Painter;
use slate_ui::text::GlyphCache;
use slate_ui::ui::Area;
use slate_ui::ui::Event;
use slate_ui::{Canvas, Color, Rect};

use crate::agent::{self, Agent, Message};
use crate::approval::{self, Dialog, Origin};
use crate::desktop::{self, Extras, Status};
use crate::displays::Arrangement;
use crate::draw::{self, ApprovalHits, PanelHits, PowerChoice, TitleButton};
use crate::fonts::{FILES, Fonts};
use crate::launcher::{self, App, Launcher};
use crate::menu::{self, Menu};
use crate::motion::{self, Motion};
use crate::power::{self, Pending, Plan, Power, Why};
use crate::server::Server;
use crate::settings::Settings;
use crate::stats::Stats;
use crate::wm::{Command, Edges, Hit, State, TitleKey, WinId, Wm, binding};
use strata_proto::PointerKind;

/// How far the launcher's floating shadow reaches past its surface
/// (logical pixels): 3σ of its blur, its offset, and a margin.
const OVERLAY_SHADOW_REACH: f32 = 200.0;

/// What super + enter starts.
pub const NEW_WINDOW: &[u8] = b"/bin/terminal";

/// The person's Flatpak apps updated in the background, when due (ADR
/// 0115).
const APP_UPDATES: &[u8] = b"/bin/slate-flatpak update --auto";
/// What a Linux program's start needs, read ahead (M31 phase 2).
const LINUX_WARM: &[u8] = b"/bin/slate-linux warm";
/// The system's updates, checked in the background (ADR 0112): only the
/// repositories' signed indexes are fetched, and the count is kept.
const UPDATE_CHECK: &[u8] = b"/bin/software-updater --check";
const UPDATER: &[u8] = b"/bin/software-updater";
/// The Clock, opened to ring an alarm when it isn't running (ADR 0104's
/// addendum).
const CLOCK: &str = "/bin/clock";

/// Where the launcher's app entries are.
pub const APP_DIR: &str = "/usr/share/strata/apps";

/// The launcher's apps.
/// The Linux runtime (ADR 0038), whose apps the launcher lists when it
/// has Sway (ADR 0039).
const LINUX_RUNTIME: &str = "/var/lib/slate/linux";

fn load_apps() -> Vec<App> {
    let mut out = Vec::new();
    if fs::exists(alloc::format!("{LINUX_RUNTIME}/usr/bin/sway").as_bytes()) {
        // The runtime's own apps, and the Flatpak apps installed for
        // everyone and for the person (ADR 0114: Flatpak exports their
        // entries; their Exec runs `flatpak run`). One installed both ways
        // shows once, the person's.
        let home = slate_rt::env::var(b"HOME").map(|h| String::from(lossy(&h))).unwrap_or_default();
        let mut dirs = alloc::vec![alloc::format!("{LINUX_RUNTIME}/usr/share/applications")];
        if fs::exists(alloc::format!("{LINUX_RUNTIME}/usr/bin/flatpak").as_bytes()) {
            if !home.is_empty() {
                dirs.push(alloc::format!("{home}/.local/share/flatpak/exports/share/applications"));
            }
            dirs.push(alloc::format!("{LINUX_RUNTIME}/var/lib/flatpak/exports/share/applications"));
        }
        let mut seen: Vec<Vec<u8>> = Vec::new();
        // The Web Browser's browser is under "Web Browser" (ADR 0115), not
        // its own entry as well.
        let browser = fs::read_file(alloc::format!("{home}/.config/strata/browser").as_bytes())
            .ok()
            .and_then(|t| String::from(lossy(&t)).lines().find_map(|l| l.trim().strip_prefix("app=").map(String::from)))
            .map(|id| alloc::format!("{id}.desktop"));
        for dir in dirs {
            for e in fs::read_dir(dir.as_bytes()).unwrap_or_default() {
                if browser.as_deref().is_some_and(|b| e.name == b.as_bytes()) {
                    continue;
                }
                if e.name.ends_with(b".desktop") && !seen.contains(&e.name) {
                    seen.push(e.name.clone());
                    let path = alloc::format!("{dir}/{}", lossy(&e.name));
                    if let Some(mut a) =
                        fs::read_file(path.as_bytes()).ok().and_then(|t| launcher::parse_desktop_entry(&lossy(&t)))
                    {
                        // Its own icon, beside its entry (M31 phase 4).
                        a.image = crate::appicons::resolve(&dir, &a.icon_name)
                            .or_else(|| {
                                (!a.flatpak.is_empty()).then(|| crate::appicons::from_catalog(&a.flatpak)).flatten()
                            })
                            .and_then(|p| crate::appicons::load(&p));
                        out.push(a);
                    }
                }
            }
        }
    }
    // Slate's apps, and the person's own entries (AppImages they added,
    // ADR 0114).
    let home = slate_rt::env::var(b"HOME").map(|h| String::from(lossy(&h))).unwrap_or_default();
    let mut dirs = alloc::vec![String::from(APP_DIR)];
    if !home.is_empty() {
        dirs.push(alloc::format!("{home}/{PERSON_APPS}"));
    }
    for dir in dirs {
        for e in fs::read_dir(dir.as_bytes()).unwrap_or_default() {
            if e.name.ends_with(b".app") {
                let path = alloc::format!("{dir}/{}", lossy(&e.name));
                if let Some(a) = fs::read_file(path.as_bytes()).ok().and_then(|t| launcher::parse_app(&lossy(&t))) {
                    out.push(a);
                }
            }
        }
    }
    out
}

/// The person's own launcher entries, from their home.
const PERSON_APPS: &str = ".local/share/strata/apps";

/// The value of `prefix` on the kernel command line (`slate.contrast=`).
pub fn cmdline_word(prefix: &str) -> Option<String> {
    let cmdline = fs::read_file(b"/proc/cmdline").unwrap_or_default();
    String::from(lossy(&cmdline)).split_whitespace().find_map(|w| w.strip_prefix(prefix)).map(String::from)
}

/// This user's full name (the comment field's first part), else the name.
fn full_name(user: &str) -> String {
    let passwd = fs::read_file(b"/etc/passwd").unwrap_or_default();
    String::from(lossy(&passwd))
        .lines()
        .find(|l| l.split(':').next() == Some(user))
        .and_then(|l| l.split(':').nth(4))
        .and_then(|g| g.split(',').next())
        .filter(|g| !g.trim().is_empty())
        .map_or_else(|| String::from(user), |g| String::from(g.trim()))
}

/// This user's name (/etc/passwd), for "Password for ...".
pub fn user_name() -> String {
    let uid = alloc::format!("{}", process::getuid());
    let passwd = fs::read_file(b"/etc/passwd").unwrap_or_default();
    String::from(lossy(&passwd))
        .lines()
        .find(|l| l.split(':').nth(2) == Some(uid.as_str()))
        .and_then(|l| l.split(':').next())
        .map_or(uid.clone(), String::from)
}

/// Where the installed system keeps Strata's fonts.
pub const FONT_DIR: &str = "/usr/share/fonts/slate";

/// Whole-number scales for large screens (docs/design/WM_STYLE.md values are
/// logical pixels).
pub fn scale_for(width: i32, height: i32) -> f32 {
    if width >= 2560 && height >= 1440 { 2.0 } else { 1.0 }
}

/// "Mon 19 Oct  14:32" (§3).
pub fn clock(tm: &slate_rt::time::Tm) -> String {
    let mut s = String::new();
    slate_rt::time::format(tm, "%a %d %b  %H:%M", &mut s);
    s
}

/// The time alone, for themes that show the date apart (ADR 0167).
pub fn time_of_day(tm: &slate_rt::time::Tm) -> String {
    let mut s = String::new();
    slate_rt::time::format(tm, "%H:%M", &mut s);
    s
}

/// The date in words, the day of the month unpadded: "Wednesday 28
/// October" (the top bar adds Sediment's comma).
pub fn date(tm: &slate_rt::time::Tm) -> String {
    let (mut day, mut month) = (String::new(), String::new());
    slate_rt::time::format(tm, "%A", &mut day);
    slate_rt::time::format(tm, "%B", &mut month);
    alloc::format!("{day} {} {month}", tm.day)
}

/// Whether the zone's files are watched ([`crate::watch`]): then the zone
/// is worked out again when [`zone_changed`] says, not by looking.
static ZONE_WATCHED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The zone's files are watched (`true`), or no longer.
pub fn zone_watched(on: bool) {
    ZONE_WATCHED.store(on, core::sync::atomic::Ordering::Relaxed);
}

/// A watch said the zone's files changed: work it out again.
pub fn zone_changed() {
    slate_rt::tz::reload();
}

/// The local time now. Where the zone's files aren't watched, every two
/// seconds they are looked at (their change times), and the zone worked
/// out again only if they changed, so that a change in Settings shows soon
/// (ADR 0039) without reading the zone table each time (ADR 0067).
pub fn local_now() -> slate_rt::time::Tm {
    use core::sync::atomic::{AtomicI64, Ordering};
    static CHECKED: AtomicI64 = AtomicI64::new(0);
    static STAMP: AtomicI64 = AtomicI64::new(i64::MIN);
    let now = slate_rt::time::unix();
    let last = CHECKED.load(Ordering::Relaxed);
    if !ZONE_WATCHED.load(Ordering::Relaxed) && (now - last >= 2 || now < last) {
        CHECKED.store(now, Ordering::Relaxed);
        let stamp = [slate_rt::tz::SETTING, b"/etc/localtime".as_slice()]
            .iter()
            .map(|p| fs::stat(p).map_or(0, |s| s.mtime.wrapping_mul(1_000_000_007).wrapping_add(s.mtime_nsec)))
            .fold(17i64, |a, m| a.wrapping_mul(31).wrapping_add(m));
        if STAMP.swap(stamp, Ordering::Relaxed) != stamp {
            slate_rt::tz::reload();
        }
    }
    slate_rt::tz::localtime(now)
}

/// The alarms in the Clock's file (`~/.config/strata/clock`).
fn clock_alarms() -> Vec<crate::alarms::Alarm> {
    let Some(home) = slate_rt::env::var(b"HOME").filter(|h| !h.is_empty()) else { return Vec::new() };
    fs::read_file(&fs::join(&home, b".config/strata/clock"))
        .map(|t| crate::alarms::read(&String::from(lossy(&t))))
        .unwrap_or_default()
}

/// Whether a default route exists (/proc/net/route: destination 0).
fn network() -> Option<bool> {
    let route = fs::read_file(b"/proc/net/route").ok()?;
    let text = String::from(lossy(&route));
    Some(text.lines().skip(1).any(|l| l.split_whitespace().nth(1) == Some("00000000")))
}

/// The first battery's charge (/sys/class/power_supply/BAT*/capacity).
fn battery() -> Option<u8> {
    for e in fs::read_dir(b"/sys/class/power_supply").ok()? {
        if e.name.starts_with(b"BAT") {
            let mut path = b"/sys/class/power_supply/".to_vec();
            path.extend_from_slice(&e.name);
            path.extend_from_slice(b"/capacity");
            let text = fs::read_file(&path).ok()?;
            return lossy(&text).trim().parse().ok();
        }
    }
    None
}

fn status() -> Status {
    let now = local_now();
    Status {
        clock: clock(&now),
        time: time_of_day(&now),
        date: date(&now),
        network: network(),
        battery: battery(),
        updates: updates(),
    }
}

/// How many updates the Software Updater's last check found
/// (`~/.cache/slate/updates`).
fn updates() -> usize {
    let Some(home) = slate_rt::env::var(b"HOME") else { return 0 };
    let path = fs::join(&home, b".cache/slate/updates");
    fs::read_file(&path).ok().and_then(|t| lossy(&t).trim().parse().ok()).unwrap_or(0)
}

/// Start `command` (a program and its arguments, by spaces) as an app of
/// this session: its process ID.
fn spawn(command: &[u8], socket: &[u8]) -> Option<i32> {
    let argv: Vec<Vec<u8>> = command.split(|&c| c == b' ').filter(|w| !w.is_empty()).map(<[u8]>::to_vec).collect();
    spawn_argv(&argv, socket)
}

/// Start a program with its arguments as an app of this session.
/// Start what the desktop asks for (ADR 0156): icons opened, and
/// Files' moves and trash.
fn desk_run(run: &[Vec<String>], socket: &[u8]) {
    for argv in run {
        let headless = ["--move-to", "--copy-to", "--trash", "--undo"];
        let what = if argv.get(1).is_some_and(|a| headless.contains(&a.as_str())) { "running" } else { "opening" };
        slate_rt::eprintln!("strata: desktop: {what} {}", argv.join(" "));
        let argv: Vec<Vec<u8>> = argv.iter().map(|a| a.as_bytes().to_vec()).collect();
        spawn_argv(&argv, socket);
    }
}

/// Files dropped on window `id` at (x, y), logical pixels on the screen
/// (ADR 0156): its app is told, unless it is a Linux program's.
fn drop_on(
    server: &mut crate::server::Server,
    wm: &mut Wm,
    id: WinId,
    (x, y): (f32, f32),
    scale: f32,
    paths: &[String],
    copy: bool,
) {
    let Some(a) = wm.frame(id) else { return };
    let c = draw::content(a, wm.title_h);
    let (cx, cy) = (((x - c.x) * scale) as i32, ((y - c.y) * scale) as i32);
    if server.drop_files(id, cx, cy, paths, copy) {
        let verb = if copy { "copied" } else { "dropped" };
        slate_rt::eprintln!("strata: {} files {verb} on window {id}", paths.len());
        wm.focus(id);
    } else {
        slate_rt::eprintln!("strata: {} files dropped on window {id}, a Linux program's: not given", paths.len());
    }
}

fn spawn_argv(argv: &[Vec<u8>], socket: &[u8]) -> Option<i32> {
    let path = argv.first().cloned()?;
    let path = path.as_slice();
    match process::fork() {
        Ok(0) => {
            // Strata ignores SIGPIPE; its programs get the default back.
            let _ = slate_rt::signal::set(slate_rt::signal::SIGPIPE, slate_rt::signal::Disposition::Default);
            let mut env: Vec<Vec<u8>> =
                slate_rt::env::vars().iter().filter(|v| !v.starts_with(b"STRATA_SOCKET=")).cloned().collect();
            let mut var = b"STRATA_SOCKET=".to_vec();
            var.extend_from_slice(socket);
            env.push(var);
            let e = process::execve(path, argv, &env);
            slate_rt::eprintln!("strata: {}: {e}", lossy(path));
            process::exit_now(127);
        }
        Ok(pid) => Some(pid),
        Err(e) => {
            slate_rt::eprintln!("strata: starting {}: {e}", lossy(path));
            None
        }
    }
}

/// The Software Updater installing what the last check found, before a
/// restart or shut down (ADR 0110's addendum): its own window shows how
/// far it is, and it ends with 0 once they are installed.
const INSTALL_UPDATES: &[u8] = b"/bin/software-updater --install";

/// How long the windows have to close before the dialog names the ones
/// still open (ms).
const CLOSE_WAIT_MS: i64 = 3000;

/// Ending the session from the power dialog (ADR 0110's addendum).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Leaving {
    plan: Plan,
    stage: Stage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Every window is to be asked to close.
    Start,
    /// They were asked at `since`; `asked`: the dialog names those still
    /// open.
    Closing {
        since: i64,
        asked: bool,
    },
    /// The updates are to be installed.
    Install,
    Installing {
        pid: i32,
    },
    /// The dialog asks whether to go on without them.
    Waiting,
    /// Restart, shut down or log out now.
    Act,
}

impl Leaving {
    fn new(plan: Plan) -> Leaving {
        Leaving { plan, stage: Stage::Start }
    }

    /// The stage after the windows have closed (or the person went on).
    fn closed(&mut self) {
        self.stage = if self.plan.install { Stage::Install } else { Stage::Act };
    }
}

/// A restart or shut down set for later: the plan, when (monotonic ms)
/// and the local time it shows.
type Timed = (Plan, i64, String);

/// What the dialog and the top bar show of `timed` at `now`.
fn pending(timed: &Option<Timed>, now: i64) -> Option<Pending> {
    timed.as_ref().map(|(plan, at, clock)| Pending::at(plan.choice, clock, plan.install, *at, now))
}

/// The power dialog with `focus` chosen, the updates the last check found
/// (none on the live system, which isn't updated) and what is set for
/// later.
fn power_dialog(focus: PowerChoice, updates: usize, live: bool, timed: &Option<Timed>, now: i64) -> Power {
    Power::new(focus).with_updates(if live { 0 } else { updates }).with_pending(pending(timed, now))
}

/// "Text Editor · notes.txt": a window still open, for the dialog.
fn window_title(w: &crate::wm::Window) -> String {
    match w.path.as_deref().filter(|p| !p.is_empty()) {
        Some(path) => alloc::format!("{} · {path}", w.app),
        None => w.app.clone(),
    }
}

/// Where the install media mark the live system (rootfs-live, M27).
pub const LIVE: &str = "/etc/slate/live";

/// The modifier bits of the protocol.
fn mod_bits(m: slate_display::input::Mods) -> u8 {
    use strata_proto::mods::*;
    (if m.shift { SHIFT } else { 0 })
        | (if m.ctrl { CTRL } else { 0 })
        | (if m.alt { ALT } else { 0 })
        | (if m.logo { LOGO } else { 0 })
        | (if m.altgr { ALTGR } else { 0 })
}

/// DM Mono's italic faces (regular, medium), which the terminal uses for
/// italics (ADR 0166).
pub const ITALIC_FILES: [&str; 2] = ["DMMono-Italic.ttf", "DMMono-MediumItalic.ttf"];

/// The italic faces from [`FONT_DIR`], those that are there (none: italics
/// are slanted).
pub fn load_italics() -> Vec<Vec<u8>> {
    ITALIC_FILES.iter().map_while(|n| fs::read_file(alloc::format!("{FONT_DIR}/{n}").as_bytes()).ok()).collect()
}

/// The themes' serifs from [`FONT_DIR`] (ADR 0175): all three, or none.
pub fn load_serifs() -> Vec<Vec<u8>> {
    let all: Vec<Vec<u8>> = crate::fonts::SERIF_FILES
        .iter()
        .map_while(|n| fs::read_file(alloc::format!("{FONT_DIR}/{n}").as_bytes()).ok())
        .collect();
    if all.len() == crate::fonts::SERIF_FILES.len() { all } else { Vec::new() }
}

/// Load Strata's fonts from [`FONT_DIR`] (apps use them too).
pub fn load_fonts() -> Result<Vec<Vec<u8>>, String> {
    FILES
        .iter()
        .map(|n| {
            let path = alloc::format!("{FONT_DIR}/{n}");
            fs::read_file(path.as_bytes()).map_err(|e| alloc::format!("{path}: {e}"))
        })
        .collect()
}

pub fn main() -> i32 {
    // A client that has gone must not take Strata with it: writes to its
    // socket fail (EPIPE) instead of killing the server.
    let _ = slate_rt::signal::set(slate_rt::signal::SIGPIPE, slate_rt::signal::Disposition::Ignore);
    let files = match load_fonts() {
        Ok(f) => f,
        Err(e) => {
            slate_rt::eprintln!("strata: {e}");
            return 1;
        }
    };
    let refs: [&[u8]; 5] = core::array::from_fn(|i| files[i].as_slice());
    let Some(mut fonts) = Fonts::new(refs) else {
        slate_rt::eprintln!("strata: the fonts in {FONT_DIR} are damaged");
        return 1;
    };
    // The themes' serifs, when they are installed (ADR 0175).
    let serifs = load_serifs();
    if let Ok(s) = <&[Vec<u8>; 3]>::try_from(serifs.as_slice()) {
        fonts = fonts.with_serifs([s[0].as_slice(), s[1].as_slice(), s[2].as_slice()]);
    }
    // Root opens the card itself; anyone else asks seatd for it.
    let card = slate_display::kms::card();
    let (fd, seat) = match fs::open(&card, fs::O_RDWR | fs::O_CLOEXEC, 0) {
        Ok(fd) => (fd, None),
        Err(direct) => match Seat::open().and_then(|mut s| Ok((s.open_device(&card)?, s))) {
            Ok((fd, s)) => (fd, Some(s)),
            Err(e) => {
                let card = String::from_utf8_lossy(&card);
                slate_rt::eprintln!("strata: no display: {card}: {direct}; {e}");
                return 1;
            }
        },
    };
    // Every display, as the person arranged them (ADR 0170).
    let mut arrangement = Arrangement::load();
    let mut screens = match Screens::open(fd, &arrangement.wants(), &|w, h| arrangement.scale_for(w, h)) {
        Ok(s) => s,
        Err(e) => {
            slate_rt::eprintln!("strata: no display: {e}");
            return 1;
        }
    };
    let mut lay = Layout::of(&screens);
    let (mut w, mut h, mut scale) = (lay.w, lay.h, lay.scale);
    report_displays(&screens, arrangement.scale.is_none());
    // Frames drawn whole free and allocate large buffers (shadows,
    // coverage, layers): keep two screens' worth of mappings and more for
    // reuse rather than map, fault in and unmap them each time (ADR
    // 0094's addendum).
    slate_rt::alloc_impl::keep_freed(2 * (w as usize * h as usize * 4) + (16 << 20));
    let socket = alloc::format!("strata-{}", process::getuid()).into_bytes();
    let mut server = match Server::listen(&socket) {
        Ok(s) => s,
        Err(e) => {
            slate_rt::eprintln!("strata: {e}");
            return 1;
        }
    };
    let mut apps = load_apps();
    server.icons = apps.iter().filter(|a| !a.linux).map(|a| (a.exec.clone(), a.icon, a.accent)).collect();
    // The app entries are read again as the launcher or the menu opens:
    // an app just installed (App Center, ADR 0125) is there at once.
    let fresh_apps = |apps: &mut Vec<App>| *apps = load_apps();
    let user = user_name();
    let mut agent = Agent::register();
    if agent.is_none() {
        slate_rt::eprintln!("strata: no approval agent (is slate-brokerd running?)");
    }
    let mut launcher: Option<Launcher> = None;
    // Where the launcher's rows were drawn, for the pointer.
    let mut launcher_rows: Vec<Area> = Vec::new();
    let mut dialog: Option<Dialog> = None;
    let mut hits = ApprovalHits::default();
    // The Applications menu and the power dialog (ADR 0110), and where
    // they were drawn.
    let mut menu: Option<Menu> = None;
    let mut menu_hits = draw::MenuHits::default();
    let mut power: Option<Power> = None;
    let mut power_hits = draw::PowerHits::default();
    // A restart or shut down set for later, what the top bar says of it,
    // and the session ending (ADR 0110's addendum).
    let mut timed: Option<Timed> = None;
    let mut pending_text: Option<String> = None;
    let mut leaving: Option<Leaving> = None;
    let mut inputs = Inputs::with_seat(w, h, seat);
    inputs.set_screen(w, h, lay.areas());
    // The system's keyboard layout (ADR 0117).
    inputs.layout = slate_display::input::system_layout();
    // New devices are opened when the kernel announces them; the rescan
    // is only a fallback.
    inputs.watch_uevents();
    inputs.rescan_ns = 10_000_000_000;
    slate_rt::eprintln!("strata: {w}x{h} at scale {scale}; input: {}", inputs.describe());
    let mut canvas = Canvas::new(w, h, Color::rgb(0));
    let mut cache = GlyphCache::new();
    // The card's 2D requests, where it does them (ADR 0172's addendum):
    // windows' contents blended into the canvas by the GPU, the canvas
    // and each window's buffer images of it; the CPU draws them otherwise
    // (and from the first request that fails on).
    let twod = slate_display::twod::TwoD::open(screens.fd());
    slate_rt::eprintln!("strata: 2D requests: {}", if twod.is_some() { "the card's" } else { "none" });
    let (mut canvas_image, mut window_images) = (None::<(u64, u32)>, slate_display::twod::Images::default());
    let mut gpu_windows = twod.is_some();
    let mut gpu_checked = false;
    // The person's settings (ADR 0039), the zone and the desktop folder,
    // read again when a watch says they changed (or looked at every two
    // seconds where they can't be watched).
    let mut settings = Settings::load();
    let mut settings_stamp = crate::settings::stamp();
    let mut settings_checked = now_ms();
    let mut pal = settings.palette();
    let mut wall = desktop::wallpapers(&pal, &settings, &lay.rects, w, h, scale);
    // The primary display's logical size: the screen the panel, the
    // launcher and the dialogs are on (ADR 0170).
    let (mut lw, mut lh) = lay.primary;
    let mut wm = Wm::new(lw, lh);
    // The theme's title bar and top bar (ADR 0167).
    wm.shape(pal.shape.title_h, pal.shape.bar_h);
    wm.set_screens(lw, lh, pal.shape.bar_h, lay.others.clone());
    let mut st = status();
    let mut status_at = now_ms();
    // Background app updates (ADR 0115): two minutes in, then hourly;
    // slate-flatpak decides whether one is due.
    let mut app_updates_at = now_ms() + 120_000;
    // The system's: five minutes in, then every six hours (not on the
    // live system, which isn't updated).
    let mut update_check_at = now_ms() + 300_000;
    // The Linux runtime warmed once, soon after the session starts, so the
    // first Linux program starts as fast as the later ones (M31 phase 2).
    let mut warm_at = Some(now_ms() + 3000);
    // The live system (M27): a way back to the installer.
    let live = fs::exists(LIVE.as_bytes());
    if live {
        slate_rt::eprintln!("strata: live session for {user}");
    }
    let mut extras = Extras { live, ..Extras::default() };
    // The desktop's icons (ADR 0102's third addendum).
    let mut desk =
        crate::desk::Desk::new(&slate_rt::env::var(b"HOME").map(|h| String::from(lossy(&h))).unwrap_or_default());
    // (After the desktop folder, which that makes.)
    let mut watcher = crate::watch::Watcher::new(&slate_rt::env::var(b"HOME").unwrap_or_default(), crate::watch::ALL);
    slate_rt::eprintln!("strata: {}", watcher.describe());
    let mut changed = 0;
    // The Clock's alarms, and the minute last looked at for them.
    let mut alarms = clock_alarms();
    let mut alarm_minute = slate_rt::time::unix().div_euclid(60);
    desk.screen = (lw, lh);
    let mut panel = PanelHits::default();
    let mut drag = Drag::None;
    // The pointer's shape, where a dragged window would snap, and the
    // window list's scroll (ADR 0039).
    let mut cursor = slate_ui::icon::Cursor::Arrow;
    let mut snap: Option<crate::wm::State> = None;
    let mut list_first = 0usize;
    let mut last_ws = wm.active;
    // The lock screen, when locked (ADR 0039), and where its "Switch
    // person" button was drawn.
    let mut locked: Option<crate::lock::Lock> = None;
    let mut lock_hits = crate::lock::Hits::default();
    // The person's picture for the lock screen, read when it locks.
    let mut face: Option<Option<slate_image::Image>> = None;
    let host = crate::greeter::hostname();
    // The last input, for locking after a while without any (ADR 0102).
    let mut last_input = now_ms();
    let full = full_name(&user);
    let mut last_title_click: (WinId, i64) = (0, i64::MIN / 2);
    let mut damage = Damage::full();
    let mut pointer_at: Option<Area> = None;
    // Motion (ADR 0038): reduced with /etc/slate/motion or the settings
    // saying so.
    let mut motion = Motion::new(settings.reduced_motion);
    let mut known: alloc::collections::BTreeSet<WinId> = alloc::collections::BTreeSet::new();
    let mut overlay_was = false;
    let mut was_moving = false;
    // The title bar button with the keyboard focus (alt + space), and
    // whether a hover fill was fading in at the last frame.
    let mut keyed: Option<(WinId, TitleButton)> = None;
    let mut hover_was_fading = false;
    let mut overlay_dim: Option<Color> = None;
    let mut overlay_layer = Canvas::new(w, h, Color::TRANSPARENT);
    // The desktop as drawn under an overlay while it fades: the frames
    // after the first copy it instead of drawing it all again (at 4K that
    // is most of each frame, M32 phase 2). Made and touched with the
    // launcher's warm-up and kept: faulting in a fresh 4K buffer took
    // longer than the first frame may.
    let mut under: Option<Canvas> = None;
    // Whether only the overlay moved at the last frame.
    let mut overlay_only_was = false;
    // A frame under an overlay goes to the screen dimmed straight from
    // `under`; the canvas then holds only the overlay's and the pointer's
    // rectangles, and the next frame without an overlay is drawn whole.
    let mut canvas_stale = false;
    // The last round read no input: the next frame waits for the
    // displays' vblanks.
    let mut paced = false;
    let mut overlay_cache = GlyphCache::new();
    // What the overlay layer shows (the launcher's state, the dialog), and
    // where on it: drawn again only when that changes, not each frame of
    // a fade.
    type MenuShown = (String, usize, usize, usize, bool);
    // (The launcher's part: its query, selection, first row shown and its
    // rows' signature.)
    type Shown = (Option<(String, usize, usize, u64)>, Option<Dialog>, Option<MenuShown>, Option<Power>);
    let mut overlay_shown: Option<Shown> = None;
    let mut overlay_bounds = Rect::new(0, 0, 0, 0);
    // The launcher is drawn once, unseen, after the first frame: its
    // glyphs and its shadow's mask are then ready when it first opens
    // (at 4K, making them took longer than a frame; M32 phase 2).
    let mut warmed = false;
    // Frame timings for the bench (ADR 0062).
    let mut stats = Stats::new(cmdline_word("strata.stats").is_some());
    // Windows whose new contents are to be drawn: their apps hear that they
    // are on the screen once the frame showing them is (protocol v8).
    let mut frame_owed: Vec<WinId> = Vec::new();
    // When the last input was read, to time the work after it.
    let mut handled_from = 0i64;
    loop {
        let loop_start = now_ns();
        let handled = if handled_from > 0 { loop_start - handled_from } else { 0 };
        // Apps hear of every change to their window's size or focus.
        let sizes: Vec<(WinId, u32, u32)> = wm
            .layout()
            .into_iter()
            .map(|(id, a)| {
                let c = draw::content(a, wm.title_h);
                (id, slate_ui::math::round(c.w * scale) as u32, slate_ui::math::round(c.h * scale) as u32)
            })
            .collect();
        server.configure(&sizes, wm.focused().map(|w| w.id), scale);
        // Started apps that have ended; the Software Updater installing
        // before a restart or shut down says how it went.
        while let Ok((pid, status)) = process::wait(-1, process::WNOHANG) {
            if pid <= 0 {
                break;
            }
            if let Some(l) = leaving.as_mut()
                && l.stage == (Stage::Installing { pid })
            {
                if process::exited(status) == Some(0) {
                    slate_rt::eprintln!("strata: power: the updates are installed");
                    l.stage = Stage::Act;
                } else {
                    slate_rt::eprintln!("strata: power: the updates weren't installed");
                    l.stage = Stage::Waiting;
                    power = Some(Power::asking(l.plan.choice, Why::NotInstalled, Vec::new()));
                    damage.set_full();
                }
            }
        }
        // The time set for a restart or shut down.
        if let Some((plan, at, _)) = &timed
            && now_ms() >= *at
            && leaving.is_none()
        {
            slate_rt::eprintln!("strata: power: the time set for {}", plan.choice.label());
            leaving = Some(Leaving::new(*plan));
            timed = None;
        }
        // Ending the session: every window is asked to close (apps with
        // unsaved work ask first), the updates are installed, and then the
        // system restarts or shuts down, or the session ends.
        if let Some(l) = leaving.as_mut() {
            let now = now_ms();
            match l.stage {
                Stage::Start => {
                    let ids: Vec<WinId> = wm.windows.iter().map(|w| w.id).collect();
                    let n = ids.len();
                    let windows = if n == 1 { "window" } else { "windows" };
                    slate_rt::eprintln!("strata: power: closing {n} {windows} to {}", l.plan.choice.label());
                    for id in ids {
                        if server.close(id, now) {
                            wm.remove(id);
                        }
                    }
                    launcher = None;
                    menu = None;
                    power = None;
                    l.stage = Stage::Closing { since: now, asked: false };
                    damage.set_full();
                }
                Stage::Closing { asked, .. } if wm.windows.is_empty() => {
                    if asked {
                        power = None;
                    }
                    l.closed();
                    damage.set_full();
                }
                Stage::Closing { since, asked: false } if now - since >= CLOSE_WAIT_MS && locked.is_none() => {
                    let apps: Vec<String> = wm.windows.iter().map(window_title).collect();
                    slate_rt::eprintln!("strata: power: still open: {}", apps.join(", "));
                    power = Some(Power::asking(l.plan.choice, Why::Unsaved, apps));
                    l.stage = Stage::Closing { since, asked: true };
                    damage.set_full();
                }
                _ => {}
            }
            if l.stage == Stage::Install {
                slate_rt::eprintln!("strata: power: installing the updates first");
                match spawn(INSTALL_UPDATES, &socket) {
                    Some(pid) if fs::exists(UPDATER) => l.stage = Stage::Installing { pid },
                    _ => {
                        l.stage = Stage::Waiting;
                        power = Some(Power::asking(l.plan.choice, Why::NotInstalled, Vec::new()));
                        damage.set_full();
                    }
                }
            }
            if l.stage == Stage::Act {
                let plan = l.plan;
                leaving = None;
                match plan.action() {
                    None => {
                        slate_rt::eprintln!("strata: leaving");
                        return 0;
                    }
                    Some(action) => {
                        slate_rt::eprintln!("strata: power: {action}");
                        if let Err(e) = agent::request(action, "") {
                            slate_rt::eprintln!("strata: power: {action}: {e}");
                            let mut p = power_dialog(plan.choice, st.updates, live, &timed, now);
                            p.error = Some(alloc::format!("{} didn't work: {e}", plan.choice.label()));
                            power = Some(p);
                            damage.set_full();
                        }
                    }
                }
            }
        }
        // Motion: the focus, new windows, minimised windows, the overlay.
        let now = now_ms();
        if now - settings_checked >= 2000 {
            settings_checked = now;
            // (An unwatched zone is looked at by local_now itself.)
            changed |= watcher.retry() | (watcher.unwatched() & !crate::watch::ZONE);
        }
        zone_watched(watcher.unwatched() & crate::watch::ZONE == 0);
        if changed & crate::watch::ZONE != 0 {
            zone_changed();
            let tm = local_now();
            slate_rt::eprintln!("strata: the time zone changed: {}", tm.zone.as_str());
            st.clock = clock(&tm);
            damage.set_full();
        }
        if changed & crate::watch::ALARMS != 0 {
            alarms = clock_alarms();
        }
        if changed & crate::watch::DESKTOP != 0 && desk.refresh() {
            damage.set_full();
        }
        // The displays: plugged in, taken out, or arranged anew (ADR 0170).
        let rearranged = changed & crate::watch::DISPLAYS != 0;
        if core::mem::take(&mut inputs.displays_changed) || rearranged {
            if rearranged {
                arrangement = Arrangement::load();
            }
            match screens.rebuild(&arrangement.wants(), &|w, h| arrangement.scale_for(w, h)) {
                Ok(()) => {
                    report_displays(&screens, arrangement.scale.is_none());
                    lay = Layout::of(&screens);
                    (w, h, scale) = (lay.w, lay.h, lay.scale);
                    (lw, lh) = lay.primary;
                    slate_rt::alloc_impl::keep_freed(2 * (w as usize * h as usize * 4) + (16 << 20));
                    canvas = Canvas::new(w, h, Color::rgb(0));
                    overlay_layer = Canvas::new(w, h, Color::TRANSPARENT);
                    under = under.map(|_| Canvas::new(w, h, Color::rgb(0)));
                    (overlay_shown, overlay_bounds, canvas_stale) = (None, Rect::new(0, 0, 0, 0), false);
                    wall = desktop::wallpapers(&pal, &settings, &lay.rects, w, h, scale);
                    wm.set_screens(lw, lh, pal.shape.bar_h, lay.others.clone());
                    desk.screen = (lw, lh);
                    inputs.set_screen(w, h, lay.areas());
                    damage = Damage::full();
                }
                Err(e) => slate_rt::eprintln!("strata: displays: {e}"),
            }
        }
        if core::mem::take(&mut changed) & crate::watch::SETTINGS != 0 {
            let stamp = crate::settings::stamp();
            if stamp != settings_stamp {
                settings_stamp = stamp;
                let new = Settings::load();
                // (A new picture of one's own keeps the settings as they
                // were; Settings writes them again to say so.)
                if new != settings || new.picture {
                    slate_rt::eprintln!("strata: settings changed: {new:?}");
                    settings = new;
                    pal = settings.palette();
                    wm.shape(pal.shape.title_h, pal.shape.bar_h);
                    wall = desktop::wallpapers(&pal, &settings, &lay.rects, w, h, scale);
                    motion.reduced = settings.reduced_motion;
                    overlay_shown = None;
                    damage.set_full();
                }
            }
        }
        motion.focus(wm.focused().map(|w| w.id), now);
        for id in wm.windows.iter().map(|w| w.id).collect::<Vec<_>>() {
            if known.insert(id) {
                motion.fade_in(id, now);
            }
        }
        known.retain(|id| wm.get(*id).is_some());
        for id in motion.minimised(now) {
            wm.minimize(id);
            damage.set_full();
        }
        // A workspace switch slides (unless motion is reduced).
        if wm.active != last_ws {
            motion.switch(last_ws, wm.active, now);
            last_ws = wm.active;
        }
        let overlay_now = launcher.is_some() || dialog.is_some() || menu.is_some() || power.is_some();
        if overlay_now != overlay_was {
            if overlay_now {
                motion.overlay_in(now);
            } else {
                motion.overlay_out(now);
                overlay_shown = None;
            }
            overlay_was = overlay_now;
        }
        let moving = motion.active(now) || locked.as_ref().is_some_and(|l| l.moving(now, settings.reduced_motion));
        // A window with the focus ends the desktop's menu and rename.
        if wm.focused().is_some() && desk.dismiss() {
            damage.set_full();
        }
        // The keyboard focus leaves the title bar with the window's focus.
        if let Some((id, _)) = keyed
            && wm.focused().map(|w| w.id) != Some(id)
        {
            keyed = None;
            damage.set_full();
        }
        // A hover fill fading in draws only its title bar, and once more
        // when it has.
        let hover_fading = motion.hovering(now);
        if (hover_fading || hover_was_fading)
            && let Some(a) = extras.hover.and_then(|(id, _)| wm.frame(id))
        {
            damage.add(Area::new(a.x, a.y, a.w, wm.title_h));
        }
        // A frame not caused by input waits for the displays' vblanks (ADR
        // 0170). Until it is drawn, nothing of what it must draw is decided
        // (its settling, whether the desktop stayed still, whether it is
        // whole): a held frame decided now would be drawn later as if
        // everything had changed.
        let deferred = paced && screens.waiting() && locked.is_none();
        let mut desk_still = false;
        if !deferred {
            hover_was_fading = hover_fading;
            // One more frame when motion stops, so its end state is shown.
            let settling = was_moving && !moving;
            was_moving = moving;
            // Nothing but the overlay's fade asks for this frame: the
            // desktop under it is as last drawn. (Its last frame too, once
            // the overlay has settled: still only it had moved.)
            let only_overlay = motion.only_overlay(now);
            desk_still = damage.is_empty() && (only_overlay || (settling && overlay_only_was));
            overlay_only_was = only_overlay;
            // While anything moves, and while an overlay dims or covers the
            // screen, draw it all.
            if moving
                || settling
                || ((launcher.is_some() || dialog.is_some() || power.is_some() || motion.overlay(now).is_some())
                    && !damage.is_empty())
            {
                damage = Damage::full();
            }
            if canvas_stale && !damage.is_empty() {
                damage.set_full();
            }
        }
        let frame_start = now_ns();
        stats.work(frame_start - loop_start, handled);
        let full_frame = damage.full;
        if damage.is_empty() {
            stats.nothing_drawn();
        }
        if let Some(l) = &locked {
            let face = face.get_or_insert_with(|| crate::faces::load(&user, process::getuid()));
            // Locked: the lock screen only, whole.
            if !damage.is_empty() {
                damage.take(w, h, scale, lay.origin);
                canvas.set_clip(canvas.bounds());
                let mut p = Painter::new(&mut canvas, &mut cache, scale).at(lay.origin, (lw, lh));
                let tm = local_now();
                let mut time = String::new();
                slate_rt::time::format(&tm, "%H:%M", &mut time);
                let date = crate::lock::date_line(&tm);
                let screen = crate::lock::Screen {
                    name: &full,
                    user: &user,
                    time: &time,
                    date: &date,
                    host: &host,
                    network: st.network,
                    battery: st.battery,
                    wall: Some(&wall),
                    face: face.as_ref(),
                    now,
                    reduced_motion: settings.reduced_motion,
                };
                // Accessibility: high contrast while locked.
                let pal = if l.high_contrast { slate_ui::graphite::Palette::pick(settings.light(), true) } else { pal };
                lock_hits = crate::lock::draw(&mut p, &pal, &fonts, &screen, l);
                let drawn = now_ns();
                screens.present_rects(&canvas.pixels, &[(0, 0, w, h)]);
                canvas_stale = false;
                stats.frame(frame_start, drawn, now_ns(), true, h as u32);
            }
        } else if !damage.is_empty() && !deferred {
            let rects = damage.take(w, h, scale, lay.origin);
            let mut shown: Vec<(usize, usize, usize, usize)> = Vec::new();
            // The colour `under` goes to the screen dimmed with, when a
            // frame does so, and the rectangles made on the canvas.
            let mut fused: Option<Color> = None;
            let mut own: Vec<Rect> = Vec::new();
            for r in rects {
                canvas.set_clip(r);
                {
                    // Where the main canvas is (to tell it from `under`).
                    let main_canvas = canvas.pixels.as_ptr() as u64;
                    let mut p = Painter::new(&mut canvas, &mut cache, scale).at(lay.origin, (lw, lh));
                    let look = |id: WinId| motion.look(id, now);
                    let (px, py) = (inputs.pointer.0 / scale + lay.origin.0, inputs.pointer.1 / scale + lay.origin.1);
                    let preview = snap.map(|s| wm.snap_area_at(s, px, py));
                    let slide = motion.slide(now, lw);
                    let ex = Extras {
                        wall: Some(&wall),
                        look: Some(&look),
                        preview,
                        list_first,
                        slide,
                        dim: settings.dim,
                        menu: menu.is_some(),
                        power: power.is_some(),
                        pending: pending_text.as_deref(),
                        desk: Some(&desk),
                        desk_keys: wm.focused().is_none(),
                        resizing: if let Drag::Resize { id, .. } = drag { Some(id) } else { None },
                        hover_in: Some(motion.hover(now)),
                        keyed,
                        ..extras
                    };
                    // A whole frame under an overlay: the desktop is drawn
                    // into `under` (or kept there from the last frame), and
                    // copied out dimmed below, in one pass.
                    let whole = full_frame && motion.overlay(now).is_some();
                    let mut client = |p: &mut Painter<'_>, id: WinId, c: Area| {
                        if let Some(b) = server.buffer(id) {
                            let r = p.device(&c);
                            let (bw, bh, serial, opaque) = (b.width as i32, b.height as i32, b.serial, b.opaque);
                            let px = b.pixels();
                            let src = &px[..(bw * bh) as usize];
                            // An opaque buffer (a Linux compositor's frames,
                            // M31) is copied, its fourth byte set.
                            if opaque {
                                p.canvas.copy_opaque(r.x, r.y, bw, bh, src);
                                return;
                            }
                            // Into the main canvas (opaque), the card blends
                            // it as draw_image would (slate-ui's colours
                            // aren't premultiplied).
                            let mine = p.canvas.pixels.as_ptr() as u64 == main_canvas;
                            if let Some(t) = twod.as_ref().filter(|_| gpu_windows && mine) {
                                let area = Rect::new(r.x, r.y, bw, bh).intersect(&p.canvas.clip());
                                if area.w <= 0 || area.h <= 0 {
                                    return;
                                }
                                let dst = match canvas_image {
                                    Some((at, id)) if at == main_canvas => Some(id),
                                    _ => {
                                        if let Some((_, old)) = canvas_image.take() {
                                            t.free(old);
                                        }
                                        let id = t.image(&p.canvas.pixels, p.canvas.width, p.canvas.height);
                                        canvas_image = id.map(|id| (main_canvas, id));
                                        id
                                    }
                                };
                                let from = (area.x - r.x, area.y - r.y);
                                let op = |s, d| {
                                    slate_display::twod::Op::blend_straight(
                                        s,
                                        from,
                                        d,
                                        (area.x, area.y),
                                        (area.w, area.h),
                                        1.0,
                                    )
                                };
                                // The first window the card draws is checked
                                // against the CPU's drawing of it (at most 1
                                // off a channel: integer against float).
                                let check = !gpu_checked;
                                let expect = check.then(|| {
                                    let mut c = Canvas::new(p.canvas.width, p.canvas.height, Color::rgb(0));
                                    c.pixels.copy_from_slice(&p.canvas.pixels);
                                    c.set_clip(area);
                                    c.draw_image(r.x, r.y, bw, bh, src);
                                    c
                                });
                                if let (Some(d), Some(s)) = (dst, window_images.of(t, serial, src, bw, bh))
                                    && t.submit(&[op(s, d)])
                                {
                                    if let Some(e) = expect {
                                        gpu_checked = true;
                                        let off = |a: u32, b: u32| {
                                            (0..4).any(|c| ((a >> (8 * c)) & 0xFF).abs_diff((b >> (8 * c)) & 0xFF) > 1)
                                        };
                                        let wrong = (area.y..area.y + area.h)
                                            .flat_map(|y| {
                                                (area.x..area.x + area.w).map(move |x| (y * e.width + x) as usize)
                                            })
                                            .filter(|&i| off(p.canvas.pixels[i], e.pixels[i]))
                                            .count();
                                        slate_rt::eprintln!(
                                            "strata: the card drew a window ({}x{}): {wrong} pixels more than 1 off the CPU's",
                                            area.w,
                                            area.h
                                        );
                                    }
                                    return;
                                }
                                slate_rt::eprintln!("strata: the card's 2D requests failed; the CPU draws windows");
                                gpu_windows = false;
                            }
                            p.canvas.draw_image(r.x, r.y, bw, bh, src);
                        }
                    };
                    if !whole {
                        panel = desktop::desktop(&mut p, &pal, &fonts, &wm, &st, ex, &mut client);
                    } else if !(desk_still && under.is_some()) {
                        // Made with the warm-up; until then, here.
                        let u = under.get_or_insert_with(|| Canvas::new(w, h, Color::TRANSPARENT));
                        u.set_clip(u.bounds());
                        let mut up = Painter::new(u, &mut *p.cache, scale).at(lay.origin, (lw, lh));
                        panel = desktop::desktop(&mut up, &pal, &fonts, &wm, &st, ex, &mut client);
                    }
                    // The overlay fades and rises in (and fades out from the
                    // last frame drawn).
                    if let Some(v) = motion.overlay(now) {
                        if overlay_now {
                            overlay_dim = if dialog.is_some() || power.is_some() {
                                Some(pal.dim_dialog)
                            } else if launcher.is_some() {
                                Some(pal.dim_launcher)
                            } else {
                                None
                            };
                            let shown: Shown = (
                                launcher.as_ref().map(|l| (l.query.clone(), l.selected, l.first, rows_signature(l))),
                                dialog.clone(),
                                menu.as_ref().map(|m| {
                                    (m.query.clone(), m.category, m.item, m.first, m.pane == menu::Pane::Apps)
                                }),
                                power.clone(),
                            );
                            if overlay_shown.as_ref() != Some(&shown) {
                                // Only where it was last drawn: the layer is
                                // transparent everywhere else.
                                overlay_layer.clear_area(overlay_bounds);
                                overlay_layer.set_clip(overlay_layer.bounds());
                                let mut lp = Painter::new(&mut overlay_layer, &mut overlay_cache, scale)
                                    .at(lay.origin, (lw, lh));
                                if let Some(l) = &launcher {
                                    let rows = l.rows();
                                    let sections = launcher::sections(&rows);
                                    let (selected, scroll) = l.view();
                                    let view =
                                        draw::Launcher { query: &l.query, sections: &sections, selected, scroll };
                                    launcher_rows = draw::launcher(&mut lp, &pal, &fonts, &view);
                                    // The surface and its shadow's reach.
                                    let a = draw::launcher_area(lw, lh, &view).grow(OVERLAY_SHADOW_REACH);
                                    overlay_bounds = lp.device(&a);
                                }
                                if let Some(m) = &menu {
                                    menu_hits = draw::apps_menu(&mut lp, &pal, &fonts, m);
                                    overlay_bounds = lp.device(&menu_hits.area.grow(OVERLAY_SHADOW_REACH));
                                }
                                if let Some(pw) = &power {
                                    let v = draw::PowerView { name: &full, user: &user, power: pw };
                                    power_hits = draw::power_dialog(&mut lp, &pal, &fonts, &v);
                                    overlay_bounds = lp.canvas.bounds();
                                }
                                if let Some(d) = &dialog {
                                    let (_, body, change) = d.texts();
                                    let details = [("requested by", d.requester.as_str()), ("change", change.as_str())];
                                    hits = draw::approval(&mut lp, &pal, &fonts, &d.view(&body, &details));
                                    overlay_bounds = lp.canvas.bounds();
                                }
                                // Down to where the layer was drawn (the
                                // shadow's real reach): less to blend each frame.
                                overlay_bounds = lp.canvas.drawn_within(overlay_bounds);
                                overlay_shown = Some(shown);
                            }
                        }
                        let rise = ((1.0 - v) * motion::RISE * scale) as i32;
                        // (Only for overlays smaller than the screen: a
                        // dialog's covers it all, and is drawn as before.)
                        let small = i64::from(overlay_bounds.w) * i64::from(overlay_bounds.h) < i64::from(w * h) / 2;
                        match (&under, overlay_dim) {
                            (Some(u), dim) if whole && small => {
                                // Only the overlay's and the pointer's
                                // rectangles are made here; the rest goes
                                // from `under` to the screen as it is shown.
                                let c = dim.map_or(Color::TRANSPARENT, |c| c.faded(v));
                                let b = overlay_bounds;
                                own.push(Rect::new(b.x, b.y + rise, b.w, b.h));
                                if inputs.pointer_seen {
                                    let (x, y) = inputs.pointer;
                                    let k = |v: f32| (v * scale) as i32;
                                    own.push(Rect::new(
                                        (x - 14.0 * scale) as i32 - 1,
                                        (y - 14.0 * scale) as i32 - 1,
                                        k(34.0) + 2,
                                        k(42.0) + 2,
                                    ));
                                }
                                for o in &own {
                                    let old = p.canvas.set_clip(*o);
                                    p.canvas.copy_dimmed(u, c);
                                    p.canvas.set_clip(old);
                                }
                                fused = Some(c);
                            }
                            (Some(u), dim) if whole => {
                                p.canvas.copy_dimmed(u, dim.map_or(Color::TRANSPARENT, |c| c.faded(v)));
                            }
                            (_, Some(c)) => draw::dim(&mut p, c, v),
                            _ => {}
                        }
                        p.canvas.composite_within(&overlay_layer, v, rise, overlay_bounds);
                    }
                }
                if inputs.pointer_seen {
                    let (x, y) = inputs.pointer;
                    slate_ui::icon::cursor(&mut canvas, x, y, scale, cursor);
                }
                // Only what was drawn goes to the display (the pointer too
                // is drawn within the damage).
                let parts = if fused.is_some() { own.clone() } else { alloc::vec![r] };
                for r in parts.iter().map(|o| o.intersect(&canvas.bounds())).filter(|o| !o.is_empty()) {
                    shown.push((r.x as usize, r.y as usize, r.w as usize, r.h as usize));
                }
            }
            list_first = panel.first;
            // Window images long undrawn let go (their buffers may be gone).
            if let Some(t) = twod.as_ref() {
                window_images.end_frame(t);
            }
            canvas.set_clip(canvas.bounds());
            if let (Some(c), Some(u)) = (fused, under.as_ref()) {
                let drawn = now_ns();
                // Each display's part; the canvas's rectangles go over it,
                // not dimmed twice.
                screens.each_buffer(|(x, y, ow, oh), words, pitch| {
                    slate_ui::canvas::dim_into(words, pitch, u, Rect::new(x, y, ow, oh), c, &own)
                });
                screens.present_rects_over(&canvas.pixels, &as_rects(&shown));
                canvas_stale = true;
                stats.frame(frame_start, drawn, now_ns(), full_frame, h as u32);
            } else if !shown.is_empty() {
                let drawn = now_ns();
                screens.present_rects(&canvas.pixels, &as_rects(&shown));
                if full_frame {
                    canvas_stale = false;
                }
                let rows = shown.iter().map(|r| r.3 as u32).sum();
                stats.frame(frame_start, drawn, now_ns(), full_frame, rows);
            }
            // The launcher, as it will open, drawn ahead on the overlay's
            // layer once the screen is settled (again after each overlay
            // has gone): the first frame that shows it has only to blend it.
            let idle = launcher.is_none() && menu.is_none() && power.is_none() && dialog.is_none();
            if idle && overlay_shown.is_none() && motion.overlay(now).is_none() {
                let l = Launcher::new(apps.clone()).with_recent(launcher::load_recent()).with_live(live);
                overlay_layer.clear_area(overlay_bounds);
                let rows = l.rows();
                let sections = launcher::sections(&rows);
                let (selected, scroll) = l.view();
                let view = draw::Launcher { query: &l.query, sections: &sections, selected, scroll };
                overlay_layer.set_clip(overlay_layer.bounds());
                let mut lp = Painter::new(&mut overlay_layer, &mut overlay_cache, scale).at(lay.origin, (lw, lh));
                draw::launcher(&mut lp, &pal, &fonts, &view);
                overlay_bounds = lp.device(&draw::launcher_area(lw, lh, &view).grow(OVERLAY_SHADOW_REACH));
                overlay_bounds = lp.canvas.drawn_within(overlay_bounds);
                overlay_shown =
                    Some((Some((l.query.clone(), l.selected, l.first, rows_signature(&l))), None, None, None));
                if !warmed {
                    warmed = true;
                    under = Some(Canvas::new(w, h, Color::rgb(0)));
                }
            }
        }
        // The frame that showed them is out (or there was nothing to draw,
        // and won't be): their apps may draw the next.
        if !deferred && !frame_owed.is_empty() {
            server.frames_shown(&frame_owed);
            frame_owed.clear();
        }
        let mut fds = server.poll_fds();
        // (The card last: its vblank events say a display has shown its
        // last frame.)
        if let Some(fd) = watcher.fd() {
            fds.push(slate_rt::io::PollFd { fd, events: slate_rt::io::POLLIN, revents: 0 });
        }
        if let Some(a) = &agent {
            fds.push(slate_rt::io::PollFd { fd: a.fd(), events: slate_rt::io::POLLIN, revents: 0 });
        }
        fds.push(slate_rt::io::PollFd { fd: screens.fd(), events: slate_rt::io::POLLIN, revents: 0 });
        // While something moves: about 60 frames a second. A motion that
        // ended while this frame was drawn still needs the next round,
        // which hides minimised windows and draws the settled state.
        let tick = moving || motion.active(now_ms()) || hover_was_fading;
        let timeout = if tick {
            16
        } else if !damage.is_empty() {
            // A frame held for a vblank.
            20
        } else if stats.pending() || leaving.is_some() {
            100
        } else {
            1000
        };
        let events = inputs.wait_input_with(timeout, &mut fds);
        server.mods = mod_bits(inputs.mods());
        // Locking by itself after the idle time the settings give.
        let now = now_ms();
        if !events.is_empty() {
            last_input = now;
        }
        // (An app showing something to watch holds it off: ADR 0102's
        // second addendum.)
        if server.inhibited() {
            last_input = now;
        }
        if locked.is_none() && settings.lock > 0 && now - last_input >= i64::from(settings.lock) * 1000 {
            slate_rt::eprintln!("strata: locked (idle)");
            launcher = None;
            menu = None;
            power = None;
            locked = Some(crate::lock::Lock::opened_at(now_ms()));
            damage.set_full();
        }
        handled_from = now_ns();
        if !events.is_empty() {
            stats.input(inputs.stamp);
            stats.read(inputs.stamp, now_ns());
        }
        if let Some(line) = stats.still(now_ns()) {
            slate_rt::eprintln!("{line}");
        }
        // The broker asks for approval, or says the request is over.
        if fds.pop().is_some_and(|p| p.revents != 0) {
            screens.read_events();
        }
        // Frames that follow input are drawn at once; the others (motion,
        // apps' new contents) wait for each display's vblank (ADR 0170).
        paced = events.is_empty();
        let agent_ready = agent.is_some() && fds.pop().is_some_and(|p| p.revents != 0);
        if watcher.fd().is_some() && fds.pop().is_some_and(|p| p.revents != 0) {
            changed |= watcher.read();
        }
        if agent_ready && let Some(a) = &mut agent {
            match a.read() {
                Some(msgs) => {
                    for m in msgs {
                        match m {
                            Message::Ask { action, requester, pid, user, error } => {
                                slate_rt::eprintln!(
                                    "strata: approval: {action} for {user} (by {requester}, pid {pid})"
                                );
                                let d = dialog
                                    .get_or_insert_with(|| Dialog::new(Origin::Agent, &action, &requester, &user));
                                if let Some(e) = error {
                                    slate_rt::eprintln!("strata: approval: try again");
                                    d.retry(&e);
                                }
                                launcher = None;
                                menu = None;
                                power = None;
                            }
                            Message::Done => {
                                if dialog.as_ref().is_some_and(|d| d.origin == Origin::Agent) {
                                    dialog = None;
                                }
                            }
                        }
                    }
                }
                None => {
                    slate_rt::eprintln!("strata: the approval agent link broke");
                    agent = None;
                }
            }
            damage.set_full();
        }
        let changes = server.handle(&fds, &mut wm);
        if changes.windows {
            damage.set_full();
        }
        for (id, r) in changes.contents {
            stats.contents(id);
            if !frame_owed.contains(&id) {
                frame_owed.push(id);
            }
            if let Some(a) = wm.layout().into_iter().find(|(w, _)| *w == id).map(|(_, a)| a) {
                // Only what the app says changed, within its content.
                let c = draw::content(a, wm.title_h);
                let (x0, y0) = (slate_ui::math::round(c.x * scale), slate_ui::math::round(c.y * scale));
                let changed = Area::new(
                    (x0 + r.x as f32) / scale,
                    (y0 + r.y as f32) / scale,
                    r.w as f32 / scale,
                    r.h as f32 / scale,
                );
                let changed = changed.intersect(&c);
                if changed.w > 0.0 && changed.h > 0.0 {
                    damage.add(changed);
                }
            }
        }
        if now_ms() >= update_check_at {
            update_check_at = now_ms() + 6 * 3_600_000;
            if !live && fs::exists(UPDATER) {
                spawn(UPDATE_CHECK, &socket);
            }
        }
        if warm_at.is_some_and(|t| now_ms() >= t) {
            warm_at = None;
            if fs::exists(alloc::format!("{LINUX_RUNTIME}/usr/bin/sway").as_bytes()) {
                spawn(LINUX_WARM, &socket);
            }
        }
        if now_ms() >= app_updates_at {
            app_updates_at = now_ms() + 3_600_000;
            if fs::exists(alloc::format!("{LINUX_RUNTIME}/usr/bin/flatpak").as_bytes()) {
                spawn(APP_UPDATES, &socket);
            }
        }
        // An alarm due with the Clock closed: the Clock opens to ring it.
        let minute = slate_rt::time::unix().div_euclid(60);
        if minute != alarm_minute {
            alarm_minute = minute;
            let tm = local_now();
            if let Some(a) = alarms.iter().find(|a| a.rings(&tm))
                && !wm.windows.iter().any(|w| w.app == "clock")
                && fs::exists(CLOCK.as_bytes())
            {
                let at = alloc::format!("{:02}:{:02}", a.hour, a.min);
                slate_rt::eprintln!("strata: the alarm at {at}: opening the Clock");
                spawn_argv(&[CLOCK.as_bytes().to_vec(), b"--ring".to_vec(), at.into_bytes()], &socket);
            }
        }
        // The top bar's facts, once a second (not on every event).
        if now_ms() - status_at >= 1000 {
            status_at = now_ms();
            let now = status();
            if now != st {
                st = now;
                damage.add(Area::new(0.0, 0.0, lw, wm.work.y));
            }
            // What is set for later counts down in its last minute.
            let p = pending(&timed, status_at);
            let text = p.as_ref().map(Pending::text);
            if text != pending_text {
                pending_text = text;
                damage.add(Area::new(0.0, 0.0, lw, wm.work.y));
            }
            if let Some(pw) = power.as_mut()
                && pw.ask.is_none()
                && pw.pending != p
            {
                pw.pending = p;
                damage.set_full();
            }
        }
        // The pointer's old place, to draw over.
        let pointer_rect = |x: f32, y: f32| {
            Area::new((x / scale + lay.origin.0) - 14.0, (y / scale + lay.origin.1) - 14.0, 34.0, 42.0)
        };
        let mut queue: alloc::collections::VecDeque<Input> = events.into();
        while let Some(ev) = queue.pop_front() {
            if let Input::Pointer(Event::PointerMove(x, y) | Event::PointerDown(x, y) | Event::PointerUp(x, y)) = ev {
                if let Some(old) = pointer_at.take() {
                    damage.add(old);
                }
                let r = pointer_rect(x, y);
                damage.add(r);
                pointer_at = Some(r);
            }
            // Locked: keys go to the lock screen, nothing to the apps.
            if let Some(l) = locked.as_mut() {
                if let Input::Pointer(Event::PointerDown(x, y)) = ev {
                    l.click_at(&lock_hits, x / scale + lay.origin.0, y / scale + lay.origin.1);
                }
                let outcome = match ev {
                    Input::Key { code, ch, mods, .. } => l.key(code, ch, mods),
                    _ => None,
                };
                if outcome == Some(crate::lock::Outcome::SwitchPerson) {
                    // The login screen comes back for someone else.
                    slate_rt::eprintln!("strata: switching person");
                    slate_rt::eprintln!("strata: leaving");
                    return 0;
                }
                if let Some(crate::lock::Outcome::Check(mut pw)) = outcome {
                    l.status = crate::lock::Status::Working;
                    let r = crate::lock::check(&pw);
                    pw.fill(0);
                    match r {
                        Ok(()) => {
                            slate_rt::eprintln!("strata: unlocked");
                            locked = None;
                            face = None;
                        }
                        Err(e) => {
                            slate_rt::eprintln!("strata: the lock screen refused ({e})");
                            l.wrong(now_ms());
                        }
                    }
                }
                damage.set_full();
                continue;
            }
            match ev {
                // The approval dialog takes every key while it is open.
                Input::Key { code, ch, mods, .. } if dialog.is_some() => {
                    let Some(d) = dialog.as_mut() else { continue };
                    match d.key(code, ch, mods) {
                        Some(approval::Outcome::Approve(pw)) => match d.origin {
                            Origin::Agent => {
                                if let Some(a) = &agent {
                                    a.answer(&pw);
                                }
                            }
                            Origin::Launcher => match agent::request(&d.action, &pw) {
                                Ok(()) => dialog = None,
                                Err(e) if e == "Authentication failure" => {
                                    d.retry("That password didn't work. Try again.")
                                }
                                Err(e) => d.retry(&e),
                            },
                        },
                        Some(approval::Outcome::Cancel) => {
                            if d.origin == Origin::Agent
                                && let Some(a) = &agent
                            {
                                a.cancel();
                            }
                            dialog = None;
                        }
                        None => {}
                    }
                    damage.set_full();
                }
                // So does the launcher (super + space closes it again).
                Input::Key { code, ch, mods, .. } if launcher.is_some() => {
                    let toggle = matches!(
                        binding(code, mods.logo, mods.shift, mods.alt),
                        Some(Command::Launcher | Command::Applications)
                    );
                    let outcome = if toggle {
                        Some(launcher::Outcome::Close)
                    } else {
                        launcher.as_mut().and_then(|l| l.key(code, ch))
                    };
                    match outcome {
                        Some(launcher::Outcome::Close) => launcher = None,
                        Some(launcher::Outcome::Open(app)) => {
                            launcher = None;
                            launcher::remember(&app.exec);
                            spawn(app.exec.as_bytes(), &socket);
                        }
                        Some(launcher::Outcome::Do(launcher::Action::Lock)) => {
                            launcher = None;
                            slate_rt::eprintln!("strata: locked");
                            locked = Some(crate::lock::Lock::opened_at(now_ms()));
                        }
                        // Restart and Power off ask in the power dialog.
                        Some(launcher::Outcome::Do(launcher::Action::Restart)) => {
                            launcher = None;
                            power = Some(power_dialog(PowerChoice::Restart, st.updates, live, &timed, now_ms()));
                        }
                        // To the installer: the session ends as Log out ends
                        // it, the windows asked to close first (g225).
                        Some(launcher::Outcome::Do(launcher::Action::Install)) => {
                            launcher = None;
                            slate_rt::eprintln!("strata: to the installer");
                            leaving = Some(Leaving::new(Plan::now(PowerChoice::LogOut)));
                        }
                        Some(launcher::Outcome::Do(launcher::Action::PowerOff)) => {
                            launcher = None;
                            power = Some(power_dialog(PowerChoice::ShutDown, st.updates, live, &timed, now_ms()));
                        }
                        Some(launcher::Outcome::Do(action)) => {
                            launcher = None;
                            match action.system() {
                                // Logging out closes the windows first, as
                                // the power dialog's Log out does.
                                None => leaving = Some(Leaving::new(Plan::now(PowerChoice::LogOut))),
                                Some(name) => dialog = Some(Dialog::new(Origin::Launcher, name, "Strata", &user)),
                            }
                        }
                        None => {}
                    }
                    damage.set_full();
                }
                // The power dialog takes every key while it is open.
                Input::Key { code, mods, .. } if power.is_some() => {
                    let outcome = power.as_mut().and_then(|p| p.key(code, mods.shift));
                    match outcome {
                        Some(power::Outcome::Cancel) => {
                            // Not ending the session after all: the apps
                            // still open stay, to save their work.
                            if leaving.take().is_some() {
                                slate_rt::eprintln!("strata: power: cancelled");
                            }
                            power = None;
                        }
                        Some(power::Outcome::Go(plan)) if !plan.leaves() => {
                            power = None;
                            slate_rt::eprintln!("strata: locked");
                            locked = Some(crate::lock::Lock::opened_at(now_ms()));
                        }
                        Some(power::Outcome::Go(plan)) if plan.minutes > 0 => {
                            let at = slate_rt::time::unix() + i64::from(plan.minutes) * 60;
                            let mut clock = String::new();
                            slate_rt::time::format(&slate_rt::tz::localtime(at), "%H:%M", &mut clock);
                            let updates = if plan.install { " after installing the updates" } else { "" };
                            slate_rt::eprintln!("strata: power: {} at {clock}{updates}", plan.action().unwrap_or("?"));
                            timed = Some((plan, now_ms() + i64::from(plan.minutes) * 60_000, clock));
                            pending_text = pending(&timed, now_ms()).as_ref().map(Pending::text);
                            power = None;
                        }
                        Some(power::Outcome::Go(plan)) => {
                            // Now, in place of anything set for later.
                            timed = None;
                            pending_text = None;
                            leaving = Some(Leaving::new(plan));
                        }
                        Some(power::Outcome::Unschedule) => {
                            if let Some((plan, _, clock)) = timed.take() {
                                slate_rt::eprintln!(
                                    "strata: power: {} at {clock} called off",
                                    plan.action().unwrap_or("?")
                                );
                            }
                            pending_text = None;
                            power = None;
                        }
                        Some(power::Outcome::Anyway(choice)) => {
                            slate_rt::eprintln!("strata: power: {} anyway", choice.label());
                            power = None;
                            match leaving.as_mut() {
                                Some(l) if matches!(l.stage, Stage::Closing { .. }) => l.closed(),
                                Some(l) => l.stage = Stage::Act,
                                None => leaving = Some(Leaving { plan: Plan::now(choice), stage: Stage::Act }),
                            }
                        }
                        None => {}
                    }
                    damage.set_full();
                }
                // So does the Applications menu (super + space trades it
                // for the launcher, super alone closes it).
                Input::Key { code, ch, mods, .. } if menu.is_some() => {
                    if binding(code, mods.logo, mods.shift, mods.alt) == Some(Command::Applications) {
                        menu = None;
                    } else if binding(code, mods.logo, mods.shift, mods.alt) == Some(Command::Launcher) {
                        menu = None;
                        fresh_apps(&mut apps);
                        launcher =
                            Some(Launcher::new(apps.clone()).with_recent(launcher::load_recent()).with_live(live));
                    } else {
                        match menu.as_mut().and_then(|m| m.key(code, ch)) {
                            Some(menu::Outcome::Close) => menu = None,
                            Some(menu::Outcome::Open(app)) => {
                                menu = None;
                                launcher::remember(&app.exec);
                                spawn(app.exec.as_bytes(), &socket);
                            }
                            None => {}
                        }
                    }
                    damage.set_full();
                }
                Input::Key { code, ch, mods, .. } => {
                    // The title bar's buttons have the keyboard focus: the
                    // keys that move along them or press one are theirs;
                    // any other leaves them and goes on as usual.
                    if let Some((id, at)) = keyed.take() {
                        if let Some(a) = wm.frame(id) {
                            damage.add(Area::new(a.x, a.y, a.w, wm.title_h));
                        }
                        let plain = !mods.logo && !mods.alt && !mods.ctrl;
                        match plain.then(|| crate::wm::title_key(at, code, mods.shift)).flatten() {
                            Some(TitleKey::Focus(b)) => {
                                keyed = Some((id, b));
                                continue;
                            }
                            Some(TitleKey::Press(b)) => {
                                slate_rt::eprintln!("strata: title bar: {b:?} by keyboard");
                                match b {
                                    TitleButton::Close => {
                                        if server.close(id, now_ms()) {
                                            wm.remove(id);
                                        }
                                    }
                                    TitleButton::Maximize => wm.toggle_maximize(id),
                                    TitleButton::Minimize => motion.fade_out(id, now_ms()),
                                }
                                damage.set_full();
                                continue;
                            }
                            Some(TitleKey::Leave) => continue,
                            None => {}
                        }
                    }
                    let Some(cmd) = binding(code, mods.logo, mods.shift, mods.alt) else {
                        // Everything else is the focused app's, or with no
                        // window focused the desktop's (ADR 0156).
                        if let Some(id) = wm.focused().map(|w| w.id) {
                            server.key(id, code, ch, mod_bits(mods));
                            stats.key_sent(id, inputs.stamp);
                        } else {
                            let out = desk.key(wm.work, code, ch, mods.shift, mods.ctrl);
                            desk_run(&out.run, &socket);
                            if out.redraw {
                                damage.set_full();
                            }
                        }
                        continue;
                    };
                    match cmd {
                        Command::Quit => {
                            slate_rt::eprintln!("strata: leaving");
                            return 2;
                        }
                        Command::Close => {
                            if let Some(id) = wm.focused().map(|w| w.id)
                                && server.close(id, now_ms())
                            {
                                wm.remove(id);
                            }
                        }
                        Command::Terminal => {
                            spawn(NEW_WINDOW, &socket);
                            continue;
                        }
                        Command::Launcher => {
                            fresh_apps(&mut apps);
                            launcher =
                                Some(Launcher::new(apps.clone()).with_recent(launcher::load_recent()).with_live(live))
                        }
                        Command::Applications => {
                            slate_rt::eprintln!("strata: the applications menu (super)");
                            fresh_apps(&mut apps);
                            menu = Some(Menu::new(apps.clone(), launcher::load_recent()));
                        }
                        Command::Lock => {
                            slate_rt::eprintln!("strata: locked");
                            locked = Some(crate::lock::Lock::opened_at(now_ms()));
                        }
                        Command::TitleButtons => {
                            if let Some(id) = wm.focused().map(|w| w.id)
                                && let Some(a) = wm.frame(id)
                            {
                                slate_rt::eprintln!("strata: title bar: keyboard focus");
                                keyed = Some((id, TitleButton::Minimize));
                                damage.add(Area::new(a.x, a.y, a.w, wm.title_h));
                            }
                            continue;
                        }
                        // Down from a half or a top quarter goes to a
                        // quarter or the half (ADR 0102); otherwise the
                        // window fades out and minimises.
                        Command::Minimize => match wm.focused().map(|w| (w.id, w.state)) {
                            Some((_, State::Left | State::Right | State::TopLeft | State::TopRight)) => {
                                wm.apply(Command::Minimize);
                            }
                            Some((id, _)) => motion.fade_out(id, now_ms()),
                            None => continue,
                        },
                        c => {
                            if !wm.apply(c) {
                                continue;
                            }
                        }
                    }
                    damage.set_full();
                }
                // The dialog is modal: only its buttons answer clicks.
                Input::Pointer(Event::PointerDown(x, y)) if dialog.is_some() => {
                    let (x, y) = (x / scale + lay.origin.0, y / scale + lay.origin.1);
                    let key = if hits.approve.contains(x, y) {
                        Some(28)
                    } else if hits.cancel.contains(x, y) {
                        Some(1)
                    } else {
                        None
                    };
                    if let (Some(code), Some(d)) = (key, dialog.as_mut()) {
                        d.focus = draw::ApprovalFocus::Password;
                        // As Enter or Esc would.
                        queue.push_back(Input::Key { code, key: None, ch: None, mods: Default::default() });
                    }
                }
                // The power dialog is modal: a click on a choice is Enter on
                // it, on Cancel or outside it Esc.
                Input::Pointer(Event::PointerDown(x, y)) if power.is_some() => {
                    let outcome = power
                        .as_mut()
                        .and_then(|p| p.click(x / scale + lay.origin.0, y / scale + lay.origin.1, &power_hits));
                    let code = match outcome {
                        // As Enter on the choice (or the other face's
                        // "anyway") would.
                        Some(power::Outcome::Go(_) | power::Outcome::Anyway(_)) => 28,
                        Some(power::Outcome::Unschedule) => {
                            if let Some(p) = power.as_mut() {
                                p.row = power::Row::Options;
                                p.at = 0;
                            }
                            28
                        }
                        Some(power::Outcome::Cancel) => 1,
                        None => {
                            // A time or the updates' box was picked.
                            damage.set_full();
                            continue;
                        }
                    };
                    if let Some(p) = power.as_mut()
                        && let Some(a) = p.ask.as_mut()
                    {
                        a.focus = usize::from(code == 28);
                    }
                    queue.push_front(Input::Key { code, key: None, ch: None, mods: Default::default() });
                }
                Input::Pointer(Event::PointerMove(..)) if power.is_some() => {}
                // The pointer over the menu: a category opens, an app is
                // chosen.
                Input::Pointer(Event::PointerMove(x, y))
                    if let Some(m) = menu.as_mut()
                        && menu_hits.area.contains(x / scale + lay.origin.0, y / scale + lay.origin.1) =>
                {
                    let (x, y) = (x / scale + lay.origin.0, y / scale + lay.origin.1);
                    let changed = if let Some(i) = menu_hits.categories.iter().position(|a| a.contains(x, y)) {
                        m.hover_category(i)
                    } else if let Some(i) = menu_hits.apps.iter().position(|a| a.contains(x, y)) {
                        m.hover_app(i)
                    } else {
                        false
                    };
                    if changed {
                        damage.set_full();
                    }
                }
                // A click on an app opens it; outside the menu, it closes.
                Input::Pointer(Event::PointerDown(x, y)) if menu.is_some() => {
                    let (x, y) = (x / scale + lay.origin.0, y / scale + lay.origin.1);
                    if let Some(i) = menu_hits.apps.iter().position(|a| a.contains(x, y)) {
                        if let Some(m) = menu.as_mut() {
                            m.hover_app(i);
                        }
                        queue.push_front(Input::Key { code: 28, key: None, ch: None, mods: Default::default() });
                    } else if let Some(i) = menu_hits.categories.iter().position(|a| a.contains(x, y)) {
                        if let Some(m) = menu.as_mut() {
                            m.hover_category(i);
                        }
                    } else if !menu_hits.area.contains(x, y) {
                        menu = None;
                    }
                    damage.set_full();
                }
                // The wheel over the menu's apps scrolls them.
                Input::Wheel { lines, x, y } if menu.is_some() => {
                    if menu_hits.apps_column.contains(x / scale + lay.origin.0, y / scale + lay.origin.1)
                        && menu.as_mut().is_some_and(|m| m.scroll(lines))
                    {
                        damage.set_full();
                    }
                }
                // The pointer over a launcher row selects it.
                Input::Pointer(Event::PointerMove(x, y))
                    if let Some(l) = launcher.as_mut()
                        && let Some(i) = launcher_rows
                            .iter()
                            .position(|a| a.contains(x / scale + lay.origin.0, y / scale + lay.origin.1)) =>
                {
                    if l.hover(i) {
                        damage.set_full();
                    }
                }
                // A click on a row opens it, as Enter would; a click outside
                // the launcher closes it.
                Input::Pointer(Event::PointerDown(x, y)) if launcher.is_some() => {
                    match launcher_rows
                        .iter()
                        .position(|a| a.contains(x / scale + lay.origin.0, y / scale + lay.origin.1))
                    {
                        Some(i) => {
                            if let Some(l) = launcher.as_mut() {
                                l.hover(i);
                            }
                            queue.push_front(Input::Key { code: 28, key: None, ch: None, mods: Default::default() });
                        }
                        None => launcher = None,
                    }
                    damage.set_full();
                }
                Input::Pointer(Event::PointerMove(x, y)) => {
                    let (x, y) = (x / scale + lay.origin.0, y / scale + lay.origin.1);
                    match drag {
                        // The window the button went down in hears every
                        // move until it comes up.
                        Drag::Content { id } => {
                            if let Some(a) = wm.frame(id) {
                                let c = draw::content(a, wm.title_h);
                                let (cx, cy) = (((x - c.x) * scale) as i32, ((y - c.y) * scale) as i32);
                                server.pointer(id, PointerKind::Move, 0, cx, cy);
                            }
                            // Files the app drags: once out of its window, a
                            // badge by the pointer, and the folder icon under
                            // it lit (ADR 0156).
                            if let Some((src, paths)) = server.drag.as_ref().filter(|d| d.0 == id) {
                                let outside = wm.frame(*src).is_none_or(|a| !a.contains(x, y));
                                let badge = outside.then_some((x, y, paths.len(), inputs.mods().ctrl));
                                let lit = if outside && !wm.in_bar(x, y) && wm.hit(x, y).is_none() {
                                    desk.hover_drop(wm.work, x, y)
                                } else {
                                    desk.target.take().is_some()
                                };
                                if badge.is_some() || extras.drag_badge.is_some() || lit {
                                    damage.set_full();
                                }
                                extras.drag_badge = badge;
                            }
                        }
                        Drag::Desk => {
                            if desk.motion(wm.work, x, y) {
                                damage.set_full();
                            }
                            // Icons dragged with ctrl held are copied: the
                            // badge says so.
                            let dragging = matches!(desk.press, Some(crate::desk::Press::Icon { dragging: true, .. }));
                            let badge = (dragging && inputs.mods().ctrl).then_some((x, y, desk.selected.len(), true));
                            if badge.is_some() || extras.drag_badge.is_some() {
                                damage.set_full();
                            }
                            extras.drag_badge = badge;
                        }
                        Drag::Move { id, dx, dy } => {
                            let before = wm.frame(id);
                            wm.move_to(id, x - dx, y - dy);
                            damage.window(before, wm.frame(id));
                            // At a screen edge: show where it would snap.
                            let target = wm.snap_target(x, y);
                            if target != snap {
                                snap = target;
                                damage.set_full();
                            }
                        }
                        Drag::Resize { id, start, edges, x0, y0 } => {
                            cursor = edges.cursor();
                            let before = wm.frame(id);
                            wm.resize(id, start, edges, x - x0, y - y0);
                            damage.window(before, wm.frame(id));
                        }
                        Drag::None => {
                            let hit = wm.hit(x, y);
                            // A double arrow over the edges that resize.
                            cursor = match hit {
                                Some(Hit::Edge(_, e)) if launcher.is_none() && dialog.is_none() => e.cursor(),
                                _ => slate_ui::icon::Cursor::Arrow,
                            };
                            // Hover: the window under the pointer hears it move.
                            if let Some(Hit::Content(id)) = hit
                                && launcher.is_none()
                                && dialog.is_none()
                                && let Some(a) = wm.frame(id)
                            {
                                let c = draw::content(a, wm.title_h);
                                let (cx, cy) = (((x - c.x) * scale) as i32, ((y - c.y) * scale) as i32);
                                server.pointer(id, PointerKind::Move, 0, cx, cy);
                            }
                            let over = match hit {
                                Some(Hit::Close(id)) => Some((id, TitleButton::Close)),
                                Some(Hit::Maximize(id)) => Some((id, TitleButton::Maximize)),
                                Some(Hit::Minimize(id)) => Some((id, TitleButton::Minimize)),
                                _ => None,
                            };
                            if over != extras.hover {
                                if over.is_some() {
                                    motion.hover_in(now_ms());
                                }
                                for id in [extras.hover.map(|h| h.0), over.map(|h| h.0)].into_iter().flatten() {
                                    if let Some(a) = wm.frame(id) {
                                        damage.add(Area::new(a.x, a.y, a.w, wm.title_h));
                                    }
                                }
                                extras.hover = over;
                            }
                        }
                    }
                }
                Input::Pointer(Event::PointerDown(x, y)) => {
                    let (x, y) = (x / scale + lay.origin.0, y / scale + lay.origin.1);
                    // A click takes the keyboard focus off the title bar.
                    if let Some(a) = keyed.take().and_then(|(id, _)| wm.frame(id)) {
                        damage.add(Area::new(a.x, a.y, a.w, wm.title_h));
                    }
                    // The desktop's menu is over everything; a click
                    // elsewhere than the desktop closes it and ends a
                    // rename.
                    if desk.menu.as_ref().is_some_and(|m| m.area(desk.screen).0.contains(x, y)) {
                        let out = desk.press(wm.work, x, y, false, false, now_ms());
                        desk_run(&out.run, &socket);
                        damage.set_full();
                        continue;
                    }
                    if (wm.in_bar(x, y) || wm.hit(x, y).is_some()) && desk.dismiss() {
                        damage.set_full();
                    }
                    if wm.in_bar(x, y) {
                        if panel.earlier.is_some_and(|a| a.contains(x, y)) {
                            list_first = panel.first.saturating_sub(1);
                        } else if panel.later.is_some_and(|a| a.contains(x, y)) {
                            list_first = panel.first + 1;
                        } else if panel.applications.contains(x, y) {
                            slate_rt::eprintln!("strata: the applications menu");
                            fresh_apps(&mut apps);
                            menu = Some(Menu::new(apps.clone(), launcher::load_recent()));
                        } else if panel.install.is_some_and(|a| a.contains(x, y)) {
                            // Leaving the live session brings the installer
                            // back (the live system's console runs it); the
                            // windows close first, as for Log out.
                            slate_rt::eprintln!("strata: to the installer");
                            leaving = Some(Leaving::new(Plan::now(PowerChoice::LogOut)));
                            damage.set_full();
                        } else if panel.updates.is_some_and(|a| a.contains(x, y)) {
                            slate_rt::eprintln!("strata: the updates");
                            spawn(UPDATER, &socket);
                        } else if panel.power.contains(x, y) || panel.pending.is_some_and(|a| a.contains(x, y)) {
                            slate_rt::eprintln!("strata: the power dialog");
                            let focus = timed.as_ref().map_or(PowerChoice::ShutDown, |t| t.0.choice);
                            power = Some(power_dialog(focus, st.updates, live, &timed, now_ms()));
                        } else if let Some(n) = panel.workspaces.iter().position(|a| a.contains(x, y)) {
                            wm.apply(Command::Workspace(n));
                        } else if let Some((i, _)) = panel.windows.iter().find(|(_, a)| a.contains(x, y)) {
                            // The window list: focus, or minimise the focused.
                            let ids: Vec<WinId> = wm.listed(wm.active).iter().map(|w| w.id).collect();
                            if let Some(&id) = ids.get(*i) {
                                if wm.focused().map(|w| w.id) == Some(id) {
                                    motion.fade_out(id, now_ms());
                                } else {
                                    let was_minimised =
                                        wm.get(id).is_some_and(|w| w.state == crate::wm::State::Minimized);
                                    wm.focus(id);
                                    if was_minimised {
                                        motion.fade_in(id, now_ms());
                                    }
                                }
                            }
                        }
                        damage.set_full();
                        continue;
                    }
                    let Some(hit) = wm.hit(x, y) else {
                        // The desktop: its icons, which now have the keys.
                        wm.unfocus();
                        let m = inputs.mods();
                        let out = desk.press(wm.work, x, y, m.ctrl, m.shift, now_ms());
                        if desk.press.is_some() {
                            drag = Drag::Desk;
                        }
                        desk_run(&out.run, &socket);
                        damage.set_full();
                        continue;
                    };
                    let id = hit.window();
                    let raised =
                        wm.focused().map(|w| w.id) != Some(id) || wm.visible().last().map(|w| w.id) != Some(id);
                    match hit {
                        Hit::Close(_) => {
                            if server.close(id, now_ms()) {
                                wm.remove(id);
                            }
                            extras.hover = None;
                        }
                        Hit::Maximize(_) => wm.toggle_maximize(id),
                        Hit::Minimize(_) => {
                            motion.fade_out(id, now_ms());
                            extras.hover = None;
                        }
                        Hit::Title(_) => {
                            wm.focus(id);
                            let now = now_ms();
                            if last_title_click.0 == id && now - last_title_click.1 < 400 {
                                wm.toggle_maximize(id);
                                last_title_click = (0, i64::MIN / 2);
                            } else {
                                last_title_click = (id, now);
                                // A maximised or snapped window comes back
                                // to its normal size under the pointer.
                                if wm.flush(id) {
                                    wm.restore(id);
                                    if let Some(r) = wm.get(id).map(|w| w.rect) {
                                        wm.move_to(id, x - r.w / 2.0, y - wm.title_h / 2.0);
                                    }
                                }
                                if let Some(a) = wm.frame(id) {
                                    drag = Drag::Move { id, dx: x - a.x, dy: y - a.y };
                                }
                            }
                        }
                        Hit::Edge(_, edges) => {
                            wm.focus(id);
                            if let Some(start) = wm.frame(id) {
                                drag = Drag::Resize { id, start, edges, x0: x, y0: y };
                            }
                        }
                        Hit::Content(_) => {
                            wm.focus(id);
                            if let Some(a) = wm.frame(id) {
                                let c = draw::content(a, wm.title_h);
                                let (cx, cy) = (((x - c.x) * scale) as i32, ((y - c.y) * scale) as i32);
                                server.pointer(id, PointerKind::Down, 1, cx, cy);
                                drag = Drag::Content { id };
                            }
                            if !raised {
                                continue;
                            }
                        }
                    }
                    damage.set_full();
                }
                Input::Pointer(Event::PointerUp(x, y)) => {
                    let (x, y) = (x / scale + lay.origin.0, y / scale + lay.origin.1);
                    if let Drag::Content { id } = drag
                        && let Some(a) = wm.frame(id)
                    {
                        let c = draw::content(a, wm.title_h);
                        server.pointer(id, PointerKind::Up, 1, ((x - c.x) * scale) as i32, ((y - c.y) * scale) as i32);
                    }
                    // Files an app dragged out of its window (ADR 0156): onto
                    // another window, or onto the desktop; copied with ctrl
                    // held.
                    let copy = inputs.mods().ctrl;
                    let app_drag = server.drag.take();
                    if extras.drag_badge.take().is_some() {
                        damage.set_full();
                    }
                    if let (Drag::Content { id }, Some((src, paths))) = (drag, app_drag)
                        && src == id
                        && wm.frame(id).is_some_and(|a| !a.contains(x, y))
                    {
                        match wm.hit(x, y).map(|h| h.window()) {
                            Some(other) => drop_on(&mut server, &mut wm, other, (x, y), scale, &paths, copy),
                            None if !wm.in_bar(x, y) => {
                                let out = desk.drop_from_app(wm.work, x, y, &paths, copy);
                                desk_run(&out.run, &socket);
                            }
                            None => {}
                        }
                        desk.target = None;
                        damage.set_full();
                    }
                    // The desktop's icons: moved, into a folder, or onto a
                    // window.
                    if let Drag::Desk = drag {
                        let over = wm.hit(x, y).map(|h| h.window());
                        let out = desk.release(wm.work, x, y, over.is_some(), copy);
                        if let (Some(paths), Some(id)) = (&out.drop, over) {
                            drop_on(&mut server, &mut wm, id, (x, y), scale, paths, copy);
                        }
                        desk_run(&out.run, &socket);
                        damage.set_full();
                    }
                    // A window dropped at a screen edge snaps there.
                    if let (Drag::Move { id, .. }, Some(s)) = (drag, snap.take()) {
                        wm.snap(id, s);
                        damage.set_full();
                    }
                    // The size in steps goes.
                    if let Drag::Resize { id, .. } = drag {
                        if let Some((cols, rows)) = wm.size_in_steps(id) {
                            slate_rt::eprintln!("strata: window {id} resized to {cols} x {rows}");
                        }
                        damage.window(wm.frame(id), wm.frame(id));
                    }
                    drag = Drag::None;
                }
                Input::Pointer(_) => {}
                // The middle and right buttons go to the window under the
                // pointer (the middle button pastes, so it focuses).
                Input::Button { button, down, x, y }
                    if dialog.is_none() && launcher.is_none() && power.is_none() && menu.is_none() =>
                {
                    let (x, y) = (x / scale + lay.origin.0, y / scale + lay.origin.1);
                    // The right button on the desktop: its menu (ADR 0156).
                    if button == 3 && down && !wm.in_bar(x, y) && wm.hit(x, y).is_none() {
                        wm.unfocus();
                        desk.right_click(wm.work, x, y);
                        damage.set_full();
                    } else if down && desk.dismiss() {
                        damage.set_full();
                    }
                    if let Some(Hit::Content(id)) = wm.hit(x, y)
                        && let Some(a) = wm.frame(id)
                    {
                        if down && wm.focused().map(|w| w.id) != Some(id) {
                            wm.focus(id);
                            damage.set_full();
                        }
                        let c = draw::content(a, wm.title_h);
                        let kind = if down { PointerKind::Down } else { PointerKind::Up };
                        server.pointer(id, kind, button, ((x - c.x) * scale) as i32, ((y - c.y) * scale) as i32);
                    }
                }
                // The wheel scrolls the launcher's list.
                Input::Wheel { lines, .. } if launcher.is_some() => {
                    if launcher.as_mut().is_some_and(|l| l.scroll(lines)) {
                        damage.set_full();
                    }
                }
                // The wheel over the panel scrolls its window list.
                Input::Wheel { lines, x, y }
                    if wm.in_bar(x / scale + lay.origin.0, y / scale + lay.origin.1)
                        && dialog.is_none()
                        && launcher.is_none()
                        && power.is_none() =>
                {
                    list_first = if lines < 0 { list_first.saturating_sub(1) } else { list_first + 1 };
                    damage.add(Area::new(0.0, 0.0, lw, wm.work.y));
                }
                // The wheel scrolls the window under the pointer.
                Input::Wheel { lines, x, y } if dialog.is_none() && launcher.is_none() && power.is_none() => {
                    let (x, y) = (x / scale + lay.origin.0, y / scale + lay.origin.1);
                    if let Some(Hit::Content(id)) = wm.hit(x, y)
                        && let Some(a) = wm.frame(id)
                    {
                        let c = draw::content(a, wm.title_h);
                        server.scroll(id, ((x - c.x) * scale) as i32, ((y - c.y) * scale) as i32, lines);
                    }
                }
                Input::Button { .. } | Input::Wheel { .. } => {}
            }
        }
    }
}

fn now_ms() -> i64 {
    now_ns() / 1_000_000
}

fn now_ns() -> i64 {
    let (s, ns) = slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC);
    s * 1_000_000_000 + ns
}

/// What a held button is doing.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Drag {
    None,
    /// Moving a window: the pointer's offset in its frame.
    Move {
        id: WinId,
        dx: f32,
        dy: f32,
    },
    /// Resizing from `start`, the pointer having started at (x0, y0).
    Resize {
        id: WinId,
        start: Area,
        edges: Edges,
        x0: f32,
        y0: f32,
    },
    /// Pressed in a window's content: the window gets the moves.
    Content {
        id: WinId,
    },
    /// Pressed on the desktop: its icons get the moves (ADR 0156).
    Desk,
}

/// Where the displays are (ADR 0170): the canvas holds them all
/// (`w` × `h` device pixels, the box around them), the primary display's
/// corner is logical (0, 0), and one scale serves every display.
#[derive(Clone, Debug)]
struct Layout {
    w: i32,
    h: i32,
    scale: f32,
    /// The logical point at the canvas's top left corner.
    origin: (f32, f32),
    /// The primary display's logical size.
    primary: (f32, f32),
    /// The other displays, logical.
    others: Vec<Area>,
    /// Every display in the canvas, device pixels, the primary first.
    rects: Vec<(i32, i32, i32, i32)>,
}

impl Layout {
    fn of(s: &Screens) -> Layout {
        let k = s.scale;
        let rects: Vec<(i32, i32, i32, i32)> = s.outputs.iter().map(|o| o.rect()).collect();
        let (px, py, pw, ph) = rects.first().copied().unwrap_or((0, 0, s.width, s.height));
        let logical = |r: &(i32, i32, i32, i32)| {
            Area::new((r.0 - px) as f32 / k, (r.1 - py) as f32 / k, r.2 as f32 / k, r.3 as f32 / k)
        };
        Layout {
            w: s.width.max(1),
            h: s.height.max(1),
            scale: k,
            origin: (-px as f32 / k, -py as f32 / k),
            primary: (pw as f32 / k, ph as f32 / k),
            others: rects.iter().skip(1).map(logical).collect(),
            rects,
        }
    }

    /// The displays' rectangles for the pointer (device pixels).
    fn areas(&self) -> Vec<(f32, f32, f32, f32)> {
        self.rects.iter().map(|r| (r.0 as f32, r.1 as f32, r.2 as f32, r.3 as f32)).collect()
    }
}

/// Say which displays are lit and where, and tell Settings
/// (`~/.cache/strata/displays-now`; `auto`: the scale isn't the person's).
fn report_displays(s: &Screens, auto: bool) {
    let lit: Vec<String> = s
        .outputs
        .iter()
        .enumerate()
        .map(|(i, o)| {
            alloc::format!(
                "{} {}x{}@{} at {},{}{}",
                o.name,
                o.mode.width,
                o.mode.height,
                o.mode.refresh,
                o.x,
                o.y,
                if i == 0 { " (primary)" } else { "" }
            )
        })
        .collect();
    slate_rt::eprintln!("strata: displays: {} at scale {}", lit.join(", "), s.scale);
    if let Err(e) = crate::displays::Now::of(s, auto).save() {
        slate_rt::eprintln!("strata: displays: {e}");
    }
}

/// Rectangles as slate-display takes them.
fn as_rects(shown: &[(usize, usize, usize, usize)]) -> Vec<(i32, i32, i32, i32)> {
    shown.iter().map(|r| (r.0 as i32, r.1 as i32, r.2 as i32, r.3 as i32)).collect()
}

/// A launcher's rows, as one number: what it shows besides its query and
/// selection (FNV-1a over the rows' texts).
fn rows_signature(l: &Launcher) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut add = |b: &[u8]| {
        for &x in b.iter().chain(&[0xFF]) {
            h = (h ^ u64::from(x)).wrapping_mul(0x0100_0000_01b3);
        }
    };
    for (label, rows) in l.rows() {
        add(label.as_bytes());
        for r in rows {
            add(r.name.as_bytes());
            add(r.meta.as_bytes());
            add(r.comment.as_bytes());
            add(&[u8::from(r.linux)]);
        }
    }
    h
}

/// Merge rectangles that overlap into one where that draws no more than
/// drawing both: a window moved a few pixels damages two rectangles that
/// are nearly the same, and drawing each would draw it twice (at 4K, most
/// of a dragged frame's cost; M32 phase 2).
fn merge_overlapping(rs: &mut Vec<Rect>) {
    let area = |r: &Rect| i64::from(r.w) * i64::from(r.h);
    let mut i = 0;
    while i < rs.len() {
        let mut merged = false;
        for j in i + 1..rs.len() {
            let (a, b) = (rs[i], rs[j]);
            let u = a.union(&b);
            if !a.intersect(&b).is_empty() && area(&u) <= area(&a) + area(&b) {
                rs[i] = u;
                rs.swap_remove(j);
                merged = true;
                break;
            }
        }
        // A grown rectangle may now overlap one already passed.
        if merged {
            i = 0;
        } else {
            i += 1;
        }
    }
}

/// The parts of the screen to draw again (ADR 0038), in logical pixels.
#[derive(Debug, Default)]
struct Damage {
    rects: Vec<Area>,
    full: bool,
}

impl Damage {
    fn full() -> Damage {
        Damage { rects: Vec::new(), full: true }
    }

    fn set_full(&mut self) {
        self.full = true;
    }

    fn is_empty(&self) -> bool {
        !self.full && self.rects.is_empty()
    }

    fn add(&mut self, a: Area) {
        if !self.full {
            self.rects.push(a);
        }
    }

    /// A window moved or resized from `before` to `after`: both, with
    /// their shadows.
    fn window(&mut self, before: Option<Area>, after: Option<Area>) {
        for a in [before, after].into_iter().flatten() {
            self.add(a.grow(desktop::SHADOW_REACH));
        }
    }

    /// The device rectangles to draw, merged into one when there are many,
    /// and cleared.
    /// (`origin`: the logical point at the canvas's corner, ADR 0170.)
    fn take(&mut self, w: i32, h: i32, scale: f32, origin: (f32, f32)) -> Vec<Rect> {
        let screen = Rect::new(0, 0, w, h);
        let to_rect = |a: &Area| {
            let (ax, ay) = (a.x - origin.0, a.y - origin.1);
            let (x0, y0) = ((ax * scale) as i32, (ay * scale) as i32);
            let (x1, y1) = (((ax + a.w) * scale) as i32 + 1, ((ay + a.h) * scale) as i32 + 1);
            Rect::new(x0, y0, x1 - x0, y1 - y0).intersect(&screen)
        };
        let out = if self.full {
            alloc::vec![screen]
        } else {
            let mut rs: Vec<Rect> = self.rects.iter().map(to_rect).filter(|r| !r.is_empty()).collect();
            merge_overlapping(&mut rs);
            if rs.len() > 6 {
                let (x0, y0) = (rs.iter().map(|r| r.x).min().unwrap_or(0), rs.iter().map(|r| r.y).min().unwrap_or(0));
                let (x1, y1) =
                    (rs.iter().map(|r| r.right()).max().unwrap_or(0), rs.iter().map(|r| r.bottom()).max().unwrap_or(0));
                rs = alloc::vec![Rect::new(x0, y0, x1 - x0, y1 - y0)];
            }
            rs
        };
        self.rects.clear();
        self.full = false;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_damage_is_drawn_once() {
        // A window moved by (12, 6): its two rectangles become one.
        let mut rs = alloc::vec![Rect::new(100, 100, 1300, 1100), Rect::new(112, 106, 1300, 1100)];
        merge_overlapping(&mut rs);
        assert_eq!(rs, [Rect::new(100, 100, 1312, 1106)]);
        // Far apart, or merging would draw much more: kept apart.
        let mut rs = alloc::vec![Rect::new(0, 0, 10, 10), Rect::new(50, 50, 10, 10)];
        merge_overlapping(&mut rs);
        assert_eq!(rs.len(), 2);
        let mut rs = alloc::vec![Rect::new(0, 0, 1000, 10), Rect::new(990, 0, 10, 1000)];
        merge_overlapping(&mut rs);
        assert_eq!(rs.len(), 2);
        // A chain: the first two merge, then the third joins them.
        let mut rs = alloc::vec![Rect::new(0, 0, 100, 100), Rect::new(200, 0, 100, 100), Rect::new(50, 0, 200, 100)];
        merge_overlapping(&mut rs);
        assert_eq!(rs, [Rect::new(0, 0, 300, 100)]);
    }
}
