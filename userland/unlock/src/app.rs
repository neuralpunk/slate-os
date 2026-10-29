// SPDX-License-Identifier: MIT OR Apache-2.0

//! The unlock program: read the partition's header, ask for the password
//! on the screen and the console at once, and try it on each key slot.
//!
//! The screen is the first card's KMS output and every evdev keyboard
//! (while it holds the display the kernel's console takes no keys from
//! them); the console is the kernel's (the serial port, and the screen
//! when there is no display). Whichever gets a password first is tried.
//! The keyboard layout is `slate.keyboard=` on the kernel command line
//! (the installer sets it), else US. Tab switches the screen to a
//! recovery key, F2 to high contrast (`slate.contrast=high` starts with
//! it); keyboards that appear are opened when their uevent comes
//! (ADR 0039).

use alloc::string::String;
use alloc::vec::Vec;

use slate_display::input::{Input, Inputs, KEY_BACKSPACE, KEY_ENTER, KEY_ESC, KEY_KPENTER, KEY_TAB, Layout};
use slate_display::kms::Display;
use slate_rt::{Errno, fs, io, lossy, process, term};
use slate_strata::fonts::Fonts;
use slate_ui::Canvas;
use slate_ui::graphite::Palette;
use slate_ui::paint::Painter;
use slate_ui::text::GlyphCache;
use slatecrypt::{Block, HEADER_BYTES, Header};

use crate::screen::{self, Mode, Status, Unlock};

/// How long a wait lasts; new keyboards come by uevent, and are looked
/// for this often besides.
const RESCAN_MS: i64 = 1000;
/// F2 (input-event-codes.h, ADR 0033).
const KEY_F2: u16 = 60;

/// The console's prompt, as the kernel's own (ADR 0036) words it.
fn prompt(device: &str) {
    io::flush_stdout();
    let _ = io::write_all(1, alloc::format!("\nThe disk is encrypted. Password to unlock {device}: ").as_bytes());
}

fn header(device: &str) -> Result<Header, String> {
    let fd =
        fs::open(device.as_bytes(), fs::O_RDONLY | fs::O_CLOEXEC, 0).map_err(|e| alloc::format!("{device}: {e}"))?;
    let mut b = alloc::vec![0u8; HEADER_BYTES];
    let mut copy = alloc::vec![0u8; HEADER_BYTES];
    let r = io::read(fd, &mut b);
    let _ = io::pread(fd, &mut copy, slatecrypt::BACKUP_OFFSET * 512);
    let _ = io::close(fd);
    if r.map_err(|e| alloc::format!("{device}: {e}"))? != HEADER_BYTES {
        return Err(alloc::format!("{device}: short read"));
    }
    Header::parse_either(&b, &copy).map_err(|e| alloc::format!("{device}: {e:?}"))
}

/// Try what was typed on every key slot (a recovery key on recovery-key
/// slots, normalized): true once the kernel has the key.
fn try_password(h: &Header, password: &[u8], memory: &mut [Block]) -> Result<bool, String> {
    let mut recovery = slatecrypt::normalize_recovery_key(password);
    let r = try_slots(h, password, recovery.as_ref(), memory);
    if let Some(r) = recovery.as_mut() {
        slatecrypt::wipe(r);
    }
    r
}

fn try_slots(h: &Header, password: &[u8], recovery: Option<&[u8; 32]>, memory: &mut [Block]) -> Result<bool, String> {
    for (i, slot) in h.slots.iter().enumerate() {
        let Some(slot) = slot else { continue };
        let secret: &[u8] = match (slot.kind, recovery) {
            (slatecrypt::SlotKind::Password, _) => password,
            (slatecrypt::SlotKind::RecoveryKey, Some(r)) => r,
            (slatecrypt::SlotKind::RecoveryKey, None) => continue,
        };
        let mut key = slatecrypt::slot_key(slot, secret, memory).map_err(|e| alloc::format!("deriving: {e:?}"))?;
        let mut r = process::unlock(i, &key);
        for _ in 0..100 {
            if r != Err(Errno::EAGAIN) {
                break;
            }
            slate_rt::time::sleep_ns(20_000_000);
            r = process::unlock(i, &key);
        }
        slatecrypt::wipe(&mut key);
        match r {
            Ok(()) => return Ok(true),
            Err(Errno::EACCES) => {}
            Err(e) => return Err(alloc::format!("handing over the key: {e}")),
        }
    }
    Ok(false)
}

/// The screen, when there is a display and the fonts.
struct Screen {
    display: Display,
    inputs: Inputs,
    fonts: Vec<Vec<u8>>,
    cache: GlyphCache,
    high_contrast: bool,
}

impl Screen {
    fn open() -> Option<Screen> {
        let fonts = slate_strata::session::load_fonts().ok()?;
        let display = Display::open().ok()?;
        let mut inputs = Inputs::new(display.width, display.height);
        inputs.layout = keyboard_layout();
        // USB keyboards come up during boot: open each as soon as its
        // uevent says it is there, so keys typed on it are not lost.
        inputs.watch_uevents();
        inputs.rescan_ns = RESCAN_MS * 1_000_000;
        let high_contrast = cmdline_word("slate.contrast=").is_some_and(|v| v == "high");
        Some(Screen { display, inputs, fonts, cache: GlyphCache::new(), high_contrast })
    }

    fn draw(&mut self, u: &Unlock<'_>) {
        let refs: [&[u8]; 5] = core::array::from_fn(|i| self.fonts[i].as_slice());
        let Some(f) = Fonts::new(refs) else { return };
        let pal = if self.high_contrast { Palette::HIGH_CONTRAST } else { Palette::GRAPHITE };
        let (w, h) = (self.display.width, self.display.height);
        let mut c = Canvas::new(w, h, pal.desktop);
        let scale = slate_strata::session::scale_for(w, h);
        let mut p = Painter::new(&mut c, &mut self.cache, scale);
        screen::draw(&mut p, &pal, &f, u);
        self.display.present(&c.pixels);
    }
}

/// The value of `prefix` on the kernel command line.
fn cmdline_word(prefix: &str) -> Option<String> {
    let cmdline = fs::read_file(b"/proc/cmdline").unwrap_or_default();
    let cmdline = String::from(lossy(&cmdline));
    cmdline.split_whitespace().find_map(|w| w.strip_prefix(prefix)).map(String::from)
}

/// `slate.keyboard=` from the kernel command line.
fn keyboard_layout() -> Layout {
    cmdline_word("slate.keyboard=").map_or(Layout::US, |l| Layout::named(&l))
}

pub fn main() -> i32 {
    let args = slate_rt::env::args();
    let Some(device) = args.get(1).map(|a| String::from(lossy(a))) else {
        slate_rt::eprintln!("usage: slate-unlock DEVICE");
        return 2;
    };
    let h = match header(&device) {
        Ok(h) => h,
        Err(e) => {
            slate_rt::eprintln!("slate-unlock: {e}");
            return 1;
        }
    };
    let blocks = h.slots.iter().flatten().map(|s| s.params.blocks()).max().unwrap_or(0);
    let mut memory = alloc::vec![Block::default(); blocks];
    let mut screen = Screen::open();
    slate_rt::eprintln!(
        "slate-unlock: asking for the password of {device}{}",
        if screen.is_some() { " on the screen and the console" } else { " on the console" }
    );
    if let Some(s) = &screen {
        slate_rt::eprintln!("slate-unlock: input: {}", s.inputs.describe());
    }
    // The console reads a line with echo off.
    let saved = term::get(0).ok();
    if let Some(t) = saved {
        let mut q = t;
        q.lflag &= !term::ECHO;
        q.lflag |= term::ICANON;
        let _ = term::set(0, &q, true);
    }
    let r = run(&device, &h, &mut memory, &mut screen);
    if let Some(t) = saved {
        let _ = term::set(0, &t, true);
    }
    match r {
        Ok(()) => 0,
        Err(e) => {
            slate_rt::eprintln!("slate-unlock: {e}");
            1
        }
    }
}

fn run(device: &str, h: &Header, memory: &mut [Block], screen: &mut Option<Screen>) -> Result<(), String> {
    let mut password: Vec<u8> = Vec::new();
    let mut line: Vec<u8> = Vec::new();
    let mut status = Status::Asking;
    let mut caps = false;
    let mut mode = Mode::Password;
    let has_recovery = h.slots.iter().flatten().any(|s| s.kind == slatecrypt::SlotKind::RecoveryKey);
    prompt(device);
    loop {
        if let Some(s) = screen.as_mut() {
            let typed = String::from(lossy(&password));
            let shown = if mode == Mode::RecoveryKey { typed.as_str() } else { "" };
            s.draw(&Unlock {
                device,
                password_len: password.chars_len(),
                status,
                caps_lock: caps,
                mode,
                typed: shown,
                has_recovery,
            });
            slatecrypt::wipe(&mut typed.into_bytes());
        }
        // Wait for keys on the screen or a line on the console.
        let mut console = [io::PollFd { fd: 0, events: io::POLLIN, revents: 0 }];
        let inputs = match screen.as_mut() {
            Some(s) => {
                let before = s.inputs.describe();
                let got = s.inputs.wait_input_with(RESCAN_MS as i32, &mut console);
                let now = s.inputs.describe();
                if now != before {
                    slate_rt::eprintln!("slate-unlock: input: {now}");
                }
                got
            }
            None => {
                let _ = io::poll(&mut console, 1000);
                Vec::new()
            }
        };
        let mut submit: Option<Vec<u8>> = None;
        for i in inputs {
            let Input::Key { code, ch, mods, .. } = i else { continue };
            caps = mods.caps;
            status = if status == Status::Wrong && code != KEY_ENTER { Status::Asking } else { status };
            match code {
                KEY_TAB => {
                    mode = if mode == Mode::Password { Mode::RecoveryKey } else { Mode::Password };
                    slatecrypt::wipe(&mut password);
                    password.clear();
                    status = Status::Asking;
                }
                KEY_F2 => {
                    if let Some(s) = screen.as_mut() {
                        s.high_contrast = !s.high_contrast;
                    }
                }
                KEY_ENTER | KEY_KPENTER
                    if mode == Mode::RecoveryKey && slatecrypt::normalize_recovery_key(&password).is_none() =>
                {
                    status = Status::NotAKey;
                }
                KEY_ENTER | KEY_KPENTER => submit = Some(core::mem::take(&mut password)),
                KEY_BACKSPACE => {
                    let mut s = String::from(lossy(&password));
                    s.pop();
                    password = s.into_bytes();
                }
                KEY_ESC => password.clear(),
                _ => {
                    if let Some(c) = ch.filter(|_| !mods.ctrl && !mods.alt && !mods.logo) {
                        // A recovery key shows in capitals, its characters only.
                        let c = match mode {
                            Mode::RecoveryKey if c.is_ascii_alphanumeric() || c == '-' => c.to_ascii_uppercase(),
                            Mode::RecoveryKey => continue,
                            Mode::Password => c,
                        };
                        let mut b = [0u8; 4];
                        password.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
                    } else if mods.ctrl && ch == Some('u') {
                        password.clear();
                    }
                }
            }
        }
        if console[0].revents != 0 {
            let mut b = [0u8; 256];
            match io::read(0, &mut b) {
                Ok(n) if n > 0 => line.extend_from_slice(&b[..n]),
                _ => {}
            }
            if let Some(end) = line.iter().position(|&c| c == b'\n' || c == b'\r') {
                let typed: Vec<u8> = line.drain(..=end).take(end).collect();
                let _ = io::write_all(1, b"\n");
                submit = Some(typed);
            }
        }
        let Some(mut pw) = submit else { continue };
        status = Status::Working;
        if let Some(s) = screen.as_mut() {
            s.draw(&Unlock {
                device,
                password_len: pw.chars_len(),
                status,
                caps_lock: caps,
                mode,
                typed: "",
                has_recovery,
            });
        }
        let opened = try_password(h, &pw, memory);
        pw.fill(0);
        if opened? {
            return Ok(());
        }
        status = Status::Wrong;
        let _ = io::write_all(1, b"That password does not unlock the disk.");
        prompt(device);
    }
}

/// The number of characters in UTF-8 bytes (the field's dots).
trait CharsLen {
    fn chars_len(&self) -> usize;
}

impl CharsLen for Vec<u8> {
    fn chars_len(&self) -> usize {
        self.iter().filter(|&&b| b & 0xC0 != 0x80).count()
    }
}
