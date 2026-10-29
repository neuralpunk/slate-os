// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-install-gui: the graphical installer on KMS and evdev (ADR 0034).
//! It draws [`gui::App`] on the display, feeds it input and carries out
//! its actions. Without a display, or with `slate.installer=text` on the
//! kernel command line, it runs the text installer instead. "Try SlateOS"
//! starts the live desktop as the live user (M27), and leaving it brings
//! the installer back; quitting leaves for the live system's login
//! prompt.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, io, lossy, process};
use slate_ui::text::GlyphCache;
use slate_ui::theme::Fonts;
use slate_ui::ui::{Event, WINDOW_H, WINDOW_W};
use slate_ui::{Canvas, Color};

use crate::gui::{self, Action, Answers, App, DiskChoice};
use crate::{Choices, Disk, NewAccount, Progress};
use slate_display::input::{Inputs, Layout};
use slate_display::kms::Display;

/// The fonts, carried in the program (it ships on the install media only,
/// ADR 0034).
static FONTS: [&[u8]; 5] = [
    include_bytes!("../../../assets/fonts/HostGrotesk-400.ttf"),
    include_bytes!("../../../assets/fonts/HostGrotesk-500.ttf"),
    include_bytes!("../../../assets/fonts/HostGrotesk-600.ttf"),
    include_bytes!("../../../assets/fonts/HostGrotesk-800.ttf"),
    include_bytes!("../../../assets/fonts/DMMono-Regular.ttf"),
];

fn exec(argv: &[&[u8]]) -> i32 {
    let args: Vec<Vec<u8>> = argv.iter().map(|a| a.to_vec()).collect();
    let e = process::execve(argv[0], &args, slate_rt::env::vars());
    slate_rt::eprintln!("slate-install-gui: {}: {e}", lossy(argv[0]));
    1
}

/// The text installer, in this process's place.
fn text_installer(live: bool) -> i32 {
    if live { exec(&[b"/bin/slate-install", b"--live"]) } else { exec(&[b"/bin/slate-install"]) }
}

/// The live system's login prompt, in this process's place.
fn login_prompt(live: bool) -> i32 {
    if live { exec(&[b"/bin/getty", b"-L", b"console", b"linux"]) } else { 0 }
}

/// "Try SlateOS" (M27): the live desktop, Strata, as the live user, in
/// this process's place (`/etc/profile` starts Strata on the console).
/// Leaving it ends the login, and the console's entry in inittab starts
/// the installer again. Without Strata, the login prompt.
fn try_desktop(live: bool) -> i32 {
    if !live {
        return 0;
    }
    if !fs::exists(b"/bin/strata") || !fs::exists(b"/etc/slate/session") {
        return login_prompt(live);
    }
    match crate::live_login("slate-install-gui") {
        0 => 0,
        _ => login_prompt(live),
    }
}

/// The scale for a screen: whole numbers while the window fits (ADR
/// 0034), smaller than 1 only on screens too small for it.
pub fn scale_for(width: i32, height: i32) -> f32 {
    let fit = (width as f32 / WINDOW_W).min(height as f32 / WINDOW_H);
    if fit >= 1.0 { (fit as i32).clamp(1, 4) as f32 } else { fit }
}

fn disk_choices(disks: &[Disk]) -> Vec<DiskChoice> {
    disks
        .iter()
        .map(|d| DiskChoice {
            name: d.name.clone(),
            kind: String::from(gui::disk_kind(&d.name, d.removable)),
            bytes: d.bytes,
            map: crate::disk_map(d).ok(),
        })
        .collect()
}

/// The answers as the install engine takes them.
pub fn choices(a: &Answers) -> Choices {
    Choices {
        root_password: None,
        account: Some(NewAccount {
            username: a.username.clone(),
            full_name: a.full_name.clone(),
            password: a.password.as_bytes().to_vec(),
        }),
        hostname: Some(a.hostname.clone()),
        locale: Some(String::from(a.locale)),
        keyboard: Some(String::from(a.keyboard)),
        timezone: Some(a.timezone.clone()),
        linux_compat: a.linux_compat,
        encrypt: a.encrypt,
        desktop: a.desktop,
        full_graphics: a.full_graphics,
        network: a.network.clone(),
        placement: a.placement.clone(),
        ..Choices::default()
    }
}

struct Screen<'f> {
    display: Display,
    canvas: Canvas,
    cache: GlyphCache,
    fonts: Fonts<'f>,
    scale: f32,
}

fn now_ms() -> i64 {
    let (s, ns) = slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC);
    s * 1000 + ns / 1_000_000
}

impl Screen<'_> {
    /// Draw a frame and show what changed (double-buffered, ADR 0101).
    fn draw(&mut self, app: &mut App, pointer: Option<(f32, f32)>) {
        app.transitions.now = now_ms();
        app.render(&mut self.canvas, &mut self.cache, &self.fonts, self.scale);
        if let Some((x, y)) = pointer {
            slate_ui::icon::pointer(&mut self.canvas, x, y, self.scale.max(1.0));
        }
        self.display.show(&self.canvas.pixels);
    }
}

pub fn main() -> i32 {
    let args = slate_rt::env::args();
    let live = args.iter().any(|a| a == b"--live");
    if live {
        crate::take_console();
    }
    let cmdline = fs::read_file(b"/proc/cmdline").unwrap_or_default();
    if lossy(&cmdline).split_whitespace().any(|w| w == "slate.installer=text") {
        return text_installer(live);
    }
    let display = match Display::open() {
        Ok(d) => d,
        Err(e) => {
            slate_rt::eprintln!("slate-install-gui: no display ({e}); starting the text installer");
            return text_installer(live);
        }
    };
    let Some(fonts) = Fonts::new(FONTS) else {
        slate_rt::eprintln!("slate-install-gui: the fonts are damaged; starting the text installer");
        drop(display);
        return text_installer(live);
    };
    let mut display = display;
    if let Err(e) = display.double_buffer() {
        slate_rt::eprintln!("slate-install-gui: one buffer only ({e})");
    }
    let (w, h) = (display.width, display.height);
    let scale = scale_for(w, h);
    let mut inputs = Inputs::new(w, h);
    slate_rt::eprintln!("slate-install-gui: {w}x{h} at scale {scale}; input: {}", inputs.describe());
    let canvas = Canvas::new(w, h, Color::rgb(0));
    let mut screen = Screen { display, canvas, cache: GlyphCache::new(), fonts, scale };

    let mut disks = crate::disks();
    let mut app = App::new(disk_choices(&disks));
    app.uefi = crate::can_go_beside();
    app.graphics_offered = slate_display::graphics::amd_cards() > 0 && slate_display::graphics::available();
    app.set_zones(crate::zone_names());
    app.set_countries(crate::region::Countries::load(), crate::region::network_zone());
    // Reduced motion, as the system says (Strata reads the same file).
    app.transitions.reduced = fs::read_file(b"/etc/slate/motion").is_ok_and(|t| lossy(&t).trim() == "reduced");
    let mut dirty = true;
    let mut last_disk_scan = 0u32;
    loop {
        if dirty {
            let pointer = inputs.pointer_seen.then_some(inputs.pointer);
            screen.draw(&mut app, pointer);
            dirty = false;
        }
        // While colours are still changing, the next frame comes soon.
        let events = inputs.wait(if app.animating() { 16 } else { 1000 });
        if app.animating() {
            dirty = true;
        }
        // Disks may appear late (USB): look again now and then before
        // one is chosen.
        last_disk_scan += 1;
        if events.is_empty() && last_disk_scan >= 2 && matches!(app.screen, gui::Screen::Welcome | gui::Screen::Disk) {
            last_disk_scan = 0;
            let now = crate::disks();
            if now.iter().map(|d| &d.name).ne(disks.iter().map(|d| &d.name)) {
                disks = now;
                app.set_disks(disk_choices(&disks));
                dirty = true;
            }
        }
        for ev in events {
            if matches!(ev, Event::PointerMove(..)) {
                dirty = true;
            }
            app.now = (slate_rt::time::monotonic_ns() / 1_000_000) as i64;
            match app.handle(ev) {
                Action::None => {}
                Action::Redraw => dirty = true,
                Action::Try => {
                    drop(screen);
                    return try_desktop(live);
                }
                Action::Quit => {
                    drop(screen);
                    return login_prompt(live);
                }
                Action::Restart => {
                    fs::sync();
                    let e = process::reboot(process::RB_AUTOBOOT);
                    slate_rt::eprintln!("slate-install-gui: restarting failed ({e})");
                }
                Action::Install(a) => {
                    install(&mut screen, &mut app, &disks, &a, &mut inputs);
                    dirty = true;
                }
            }
        }
        inputs.layout = Layout::named(app.keyboard());
    }
}

/// Run the install, showing its progress.
fn install(screen: &mut Screen<'_>, app: &mut App, disks: &[Disk], a: &Answers, inputs: &mut Inputs) {
    let Some(disk) = disks.iter().find(|d| d.name == a.disk) else {
        app.failure = Some(format!("The disk {} is gone.", a.disk));
        return;
    };
    let c = choices(a);
    let mut shown = (usize::MAX, -1i32);
    let pointer = inputs.pointer_seen.then_some(inputs.pointer);
    let r = crate::install_on(disk, &c, &mut |p: Progress| {
        let (stage, fraction) = gui::stage_of(p);
        // Redraw when the stage or the whole percentage changes.
        let key = (stage, (fraction * 100.0) as i32);
        if key != shown {
            shown = key;
            app.set_progress(stage, fraction);
            screen.draw(app, pointer);
        }
    });
    match r {
        Ok(()) => {
            slate_rt::eprintln!("slate-install-gui: installed on {}", disk.name);
            app.finished();
        }
        Err(e) => {
            slate_rt::eprintln!("slate-install-gui: the installation failed: {e}");
            app.failure = Some(e);
        }
    }
    // Input that arrived meanwhile is stale.
    let _ = inputs.wait(0);
    let _ = io::flush_stdout();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scales() {
        assert_eq!(scale_for(1280, 800), 1.0);
        assert_eq!(scale_for(1920, 1080), 1.0);
        assert_eq!(scale_for(2560, 1600), 2.0);
        assert_eq!(scale_for(3840, 2160), 3.0);
        assert!((scale_for(800, 600) - 800.0 / 860.0).abs() < 1e-6);
    }
}
