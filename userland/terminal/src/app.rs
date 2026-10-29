// SPDX-License-Identifier: MIT OR Apache-2.0

//! The terminal app: a Strata window, a pseudo-terminal and the user's
//! shell on it. Output feeds the emulator; keys become the bytes an xterm
//! sends; the window's title follows the foreground program and its
//! directory, naming its process so Strata can show its domain.
//!
//! It keeps 10,000 lines of scrollback (the wheel, shift + PgUp/PgDn; new
//! output or typing returns to the bottom), selects with the mouse, and
//! copies and pastes through Strata's clipboards: ctrl + shift + c/v, the
//! selection on release, the middle button or shift + Insert to paste it
//! (ADR 0038); ctrl + shift + a selects all.
//!
//! A program that asks for the mouse gets it (ADR 0099), except with
//! shift held, which selects as usual. The right button opens a menu of
//! the clipboard actions. Keys and pastes go to the program through a
//! queue on the non-blocking pseudo-terminal, so a program that doesn't
//! read never stops the window. The colours follow the person's light
//! variant and high contrast settings as they change.

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{Errno, fs, io, lossy, process, term};
use slate_strata::settings::{self, Settings};
use slate_strata_client::mods::SHIFT;
use slate_strata_client::{Connection, Event, PointerKind, Window, clipboard};
use slate_term::vt::{MouseMode, Term};
use slate_ui::paint::Painter;
use slate_ui::text::GlyphCache;

use crate::keys::{self, Local};
use crate::menu::{Item, Menu, Outcome};
use crate::mouse::{self, Action};
use crate::outbox::Outbox;
use crate::render::{self, Cursor, Metrics, Theme, View};
use crate::select::{self as sel, Point, Selection, Unit};
use slate_strata::fonts::Fonts;

/// SIGHUP (signal(7)).
const SIGHUP: i32 = 1;
/// How long the cursor stays chalk after a key (ms).
const TYPING_MS: i64 = 600;
/// The scrollback's length, in lines.
const SCROLLBACK: usize = 10_000;
/// Lines a notch of the wheel scrolls.
const WHEEL_LINES: i64 = 3;
/// Clicks closer than this (ms) count as a double or triple click.
const MULTI_CLICK_MS: i64 = 400;
/// evdev's arrow keys (input-event-codes.h), sent for the wheel in
/// full-screen programs.
const KEY_UP: u16 = 103;
const KEY_DOWN: u16 = 108;
/// How often the settings file is looked at (ms), as Strata does.
const SETTINGS_MS: i64 = 2000;

fn now_ms() -> i64 {
    let (s, ns) = slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC);
    s * 1000 + ns / 1_000_000
}

/// A colour as an SGR foreground parameter, `38;2;R;G;B`.
pub fn sgr(c: slate_ui::Color) -> String {
    alloc::format!("38;2;{};{};{}", (c.0 >> 16) & 0xFF, (c.0 >> 8) & 0xFF, c.0 & 0xFF)
}

/// Start the shell on the pty's other side; its pid. The prompt's colours
/// come from the theme (ADR 0124, ADR 0167): `STRATA_PROMPT_PATH` is
/// `muted`, `STRATA_PROMPT_SIGN` `inactive` (the accent in the themes in
/// colour), `STRATA_PROMPT_USER` the user's (bright white, 97, unless the
/// theme says), which /etc/profile's PS1 uses.
fn start_shell(slave: &[u8], theme: &Theme) -> Result<i32, String> {
    let pal = &theme.pal;
    let shell = slate_rt::env::var(b"SHELL").filter(|s| !s.is_empty()).unwrap_or_else(|| b"/bin/sh".to_vec());
    match process::fork() {
        Ok(0) => {
            let _ = process::setsid();
            if let Ok(fd) = fs::open(slave, fs::O_RDWR, 0) {
                for n in 0..3 {
                    let _ = process::dup2(fd, n);
                }
                if fd > 2 {
                    let _ = io::close(fd);
                }
            }
            let _ = term::set_controlling(0);
            if let Some(home) = slate_rt::env::var(b"HOME") {
                let _ = fs::chdir(&home);
            }
            let mut env: Vec<Vec<u8>> = slate_rt::env::vars()
                .iter()
                .filter(|v| {
                    ![
                        &b"TERM="[..],
                        b"STRATA_TERMINAL=",
                        b"STRATA_PROMPT_PATH=",
                        b"STRATA_PROMPT_SIGN=",
                        b"STRATA_PROMPT_USER=",
                    ]
                    .iter()
                    .any(|p| v.starts_with(p))
                })
                .cloned()
                .collect();
            env.push(b"TERM=xterm-256color".to_vec());
            env.push(b"STRATA_TERMINAL=1".to_vec());
            env.push(alloc::format!("STRATA_PROMPT_PATH={}", sgr(pal.muted)).into_bytes());
            env.push(alloc::format!("STRATA_PROMPT_SIGN={}", sgr(theme.prompt_sign)).into_bytes());
            let user = theme.prompt_user.map_or(String::from("97"), sgr);
            env.push(alloc::format!("STRATA_PROMPT_USER={user}").into_bytes());
            let e = process::execve(&shell, &[shell.clone(), b"-l".to_vec()], &env);
            slate_rt::eprintln!("terminal: {}: {e}", lossy(&shell));
            process::exit_now(127)
        }
        Ok(pid) => Ok(pid),
        Err(e) => Err(alloc::format!("starting the shell: {e}")),
    }
}

/// What the title shows: the foreground program ("terminal" for the shell
/// itself), its directory with `~` for home, and its pid.
fn title(master: i32, shell: i32, home: &str) -> (String, String, i32) {
    let fg = term::foreground(master).ok().filter(|&p| p > 0).unwrap_or(shell);
    let name = |pid: i32| {
        fs::read_file(alloc::format!("/proc/{pid}/comm").as_bytes())
            .map(|c| String::from(lossy(&c).trim()))
            .unwrap_or_default()
    };
    let app = if fg == shell { String::from("terminal") } else { name(fg) };
    let cwd =
        fs::readlink(alloc::format!("/proc/{fg}/cwd").as_bytes()).map(|c| String::from(lossy(&c))).unwrap_or_default();
    let path = match cwd.strip_prefix(home) {
        Some(rest) if !home.is_empty() && (rest.is_empty() || rest.starts_with('/')) => alloc::format!("~{rest}"),
        _ => cwd,
    };
    (app, path, fg)
}

/// A terminal window's line in utmp and wtmp, written by the broker:
/// `who` and `w` list the window while it is open.
struct Record(i32);

impl Record {
    fn login(slave: &[u8], shell: i32) -> Record {
        let line = slave.strip_prefix(b"/dev/").unwrap_or(slave);
        // The broker checks that the shell is on the terminal: wait (a
        // second at most) until it has made it its own (proc(5)'s stat
        // field 7).
        for _ in 0..50 {
            let stat = fs::read_file(alloc::format!("/proc/{shell}/stat").as_bytes()).unwrap_or_default();
            let after = stat.iter().rposition(|&c| c == b')').map_or(&stat[..], |i| &stat[i + 1..]);
            let tty = after.split(|c| c.is_ascii_whitespace()).filter(|w| !w.is_empty()).nth(4);
            if tty.is_some_and(|t| t != b"0") {
                break;
            }
            slate_rt::time::sleep_ns(20_000_000);
        }
        if let Err(e) = slate_strata::agent::ask(&[b"record", b"login", line, alloc::format!("{shell}").as_bytes()]) {
            slate_rt::eprintln!("terminal: no login record ({e})");
        }
        Record(shell)
    }
}

impl Drop for Record {
    fn drop(&mut self) {
        let _ = slate_strata::agent::ask(&[b"record", b"logout", alloc::format!("{}", self.0).as_bytes()]);
    }
}

struct Session<'f> {
    conn: Connection,
    win: Window,
    fonts: &'f Fonts<'f>,
    italics: &'f render::Italics<'f>,
    metrics: Metrics,
    term: Term,
    master: i32,
    cache: GlyphCache,
    /// The canvas drawn into, kept while the window keeps its size.
    canvas: Option<slate_ui::Canvas>,
    /// Lines scrolled back.
    view: usize,
    selection: Option<Selection>,
    /// The left button is down, selecting.
    selecting: bool,
    /// The last click: when, where (line and cell), and how many in a row.
    last_click: (i64, Point, u32),
    theme: Theme,
    /// The settings file's time stamp when last read.
    settings_stamp: Option<(i64, i64)>,
    /// Bytes waiting for the program.
    out: Outbox,
    /// The right-click menu, and whether the pointer moved since it opened
    /// (until it does, the release of the button that opened it is no
    /// choice).
    menu: Option<(Menu, bool)>,
    /// While the program hears the mouse: the button held, and the cell
    /// last reported.
    held: Option<u8>,
    reported: Option<(usize, usize)>,
}

impl Session<'_> {
    /// Fit the grid to the window, and tell the pty. The text is wrapped
    /// again, so a selection (by line numbers) no longer holds.
    fn fit(&mut self) {
        let was = self.metrics.scale;
        self.metrics = Metrics::new(self.fonts, self.win.scale);
        if was != self.metrics.scale {
            let _ = steps(&mut self.conn, &self.win, &self.metrics);
        }
        let (cols, rows) = self.metrics.grid(self.win.width, self.win.height);
        if (cols, rows) != (self.term.cols(), self.term.rows()) {
            self.term.resize(cols, rows);
            self.selection = None;
            self.selecting = false;
            self.view = 0;
        }
        let _ = term::set_size(self.master, rows as u16, cols as u16);
    }

    fn draw(&mut self, typing: bool) -> Result<(), String> {
        let pal = self.theme.pal;
        let (w, h) = (self.win.width.max(1) as i32, self.win.height.max(1) as i32);
        let mut canvas = match self.canvas.take() {
            Some(c) if c.width == w && c.height == h => c,
            _ => self.win.canvas(pal.window),
        };
        let c = Cursor { focused: self.win.focused, typing };
        let view = View { offset: self.view, span: self.selection.map(|s| s.span(&self.term)) };
        render::draw(
            &mut canvas,
            &mut self.cache,
            self.fonts,
            self.italics,
            &self.theme,
            &self.term,
            &self.metrics,
            c,
            &view,
        );
        if let Some((m, _)) = &self.menu {
            let mut p = Painter::new(&mut canvas, &mut self.cache, self.win.scale);
            m.draw(&mut p, &pal, self.fonts);
        }
        let r = self.conn.present(&mut self.win, &canvas);
        self.canvas = Some(canvas);
        r
    }

    /// Queue bytes for the program and write what it takes.
    fn send(&mut self, bytes: &[u8]) {
        self.out.push(bytes);
        self.flush();
    }

    fn flush(&mut self) {
        let master = self.master;
        let _ = self.out.flush(|b| io::write(master, b));
    }

    /// The settings changed: the colours follow. True if they did.
    fn follow_settings(&mut self) -> bool {
        let stamp = settings::stamp();
        if stamp == self.settings_stamp {
            return false;
        }
        self.settings_stamp = stamp;
        let s = Settings::load();
        let theme = Theme::pick(s.theme, s.high_contrast);
        let changed = theme.pal != self.theme.pal;
        self.theme = theme;
        // A new background for the window.
        self.canvas = None;
        changed
    }

    /// Scroll the view by `lines` (< 0: back), within the scrollback.
    fn scroll(&mut self, lines: i64) {
        let max = self.term.history_len() as i64;
        self.view = (self.view as i64 - lines).clamp(0, max) as usize;
    }

    /// The text position under a point of the window (device pixels):
    /// (the line, the nearest column boundary, the cell).
    fn locate(&self, x: i32, y: i32) -> (u64, usize, usize) {
        let t = &self.term;
        let (row, boundary, cell) = self.metrics.locate(x, y, t.rows(), t.cols());
        let top = t.dropped() + (t.history_len() - self.view.min(t.history_len())) as u64;
        (top + row as u64, boundary, cell)
    }

    fn point(&self, x: i32, y: i32, unit: Unit) -> Point {
        let (line, boundary, cell) = self.locate(x, y);
        Point { line, col: if unit == Unit::Char { boundary } else { cell } }
    }

    /// Whether the program hears the mouse now: it asked, and shift isn't
    /// held (shift selects, as in xterm).
    fn reporting(&self, mods: u8) -> bool {
        self.term.mouse != MouseMode::Off && mods & SHIFT == 0
    }

    /// Tell the program what the mouse did at (`x`, `y`).
    fn report(&mut self, action: Action, x: i32, y: i32, mods: u8) {
        let (row, _, col) = self.metrics.locate(x, y, self.term.rows(), self.term.cols());
        if matches!(action, Action::Move(_)) && self.reported == Some((col, row)) {
            return;
        }
        self.reported = Some((col, row));
        if let Some(bytes) = mouse::report(self.term.mouse, self.term.mouse_encoding, action, col, row, mods) {
            self.send(&bytes);
        }
    }

    /// A pointer event; true if the window needs drawing.
    fn pointer(&mut self, kind: PointerKind, button: u8, x: i32, y: i32, mods: u8) -> Result<bool, String> {
        let scale = self.win.scale;
        let (lx, ly) = (x as f32 / scale, y as f32 / scale);
        if let Some((mut m, moved)) = self.menu {
            return Ok(match kind {
                PointerKind::Move => {
                    let changed = m.hover(lx, ly);
                    self.menu = Some((m, true));
                    changed
                }
                PointerKind::Up if !moved => false,
                PointerKind::Up => match m.click(lx, ly) {
                    Outcome::Open => false,
                    Outcome::Closed => {
                        self.menu = None;
                        true
                    }
                    Outcome::Chose(item) => {
                        self.menu = None;
                        self.act(item)?;
                        true
                    }
                },
                PointerKind::Down if m.area().contains(lx, ly) => {
                    self.menu = Some((m, true));
                    false
                }
                PointerKind::Down => {
                    self.menu = None;
                    true
                }
            });
        }
        if self.reporting(mods) && !self.selecting {
            let action = match kind {
                PointerKind::Down => {
                    self.held = Some(button);
                    Action::Press(button)
                }
                PointerKind::Up => {
                    self.held = None;
                    Action::Release(button)
                }
                PointerKind::Move => Action::Move(self.held),
            };
            self.report(action, x, y, mods);
            return Ok(false);
        }
        match (kind, button) {
            (PointerKind::Down, 1) => {
                let now = now_ms();
                let (line, _, cell) = self.locate(x, y);
                let here = Point { line, col: cell };
                let (at, there, n) = self.last_click;
                let n = if now - at < MULTI_CLICK_MS && there == here { n + 1 } else { 1 };
                self.last_click = (now, here, n);
                let unit = Unit::for_clicks(n);
                self.selection = Some(Selection::new(self.point(x, y, unit), unit));
                self.selecting = true;
                Ok(true)
            }
            (PointerKind::Move, _) if self.selecting => {
                // Dragging past the top or bottom scrolls.
                if (y as f32) < self.metrics.pad_y {
                    self.scroll(-1);
                } else if y as f32 > self.win.height as f32 - self.metrics.pad_y {
                    self.scroll(1);
                }
                let Some(mut sel) = self.selection else { return Ok(false) };
                let head = self.point(x, y, sel.unit);
                if head == sel.head {
                    return Ok(false);
                }
                sel.head = head;
                self.selection = Some(sel);
                Ok(true)
            }
            (PointerKind::Up, 1) if self.selecting => {
                self.selecting = false;
                match self.selection {
                    Some(sel) if !sel.is_empty(&self.term) => {
                        let text = sel.text(&self.term);
                        self.conn.copy(clipboard::SELECTION, &text)?;
                    }
                    _ => self.selection = None,
                }
                Ok(true)
            }
            (PointerKind::Down, 2) => {
                self.conn.paste(&self.win, clipboard::SELECTION)?;
                Ok(false)
            }
            (PointerKind::Down, 3) => {
                let can_copy = self.selection.is_some_and(|s| !s.is_empty(&self.term));
                let (w, h) = (self.win.width as f32 / scale, self.win.height as f32 / scale);
                self.menu = Some((Menu::open(lx, ly, w, h, can_copy), false));
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// A menu item.
    fn act(&mut self, item: Item) -> Result<(), String> {
        match item {
            Item::Copy => self.local(Local::Copy),
            Item::Paste => self.local(Local::Paste),
            Item::SelectAll => self.local(Local::SelectAll),
            Item::ClearScrollback => {
                self.term.clear_scrollback();
                self.selection = None;
                self.view = 0;
                Ok(())
            }
        }
    }

    /// A key the terminal keeps.
    fn local(&mut self, l: Local) -> Result<(), String> {
        let page = self.term.rows().saturating_sub(1).max(1) as i64;
        match l {
            Local::PageUp => self.scroll(-page),
            Local::PageDown => self.scroll(page),
            Local::Copy => {
                if let Some(sel) = self.selection.filter(|s| !s.is_empty(&self.term)) {
                    let text = sel.text(&self.term);
                    self.conn.copy(clipboard::CLIPBOARD, &text)?;
                }
            }
            Local::Paste => self.conn.paste(&self.win, clipboard::CLIPBOARD)?,
            Local::PasteSelection => self.conn.paste(&self.win, clipboard::SELECTION)?,
            Local::SelectAll => {
                let all = sel::all(&self.term);
                self.selection = Some(all);
                if !all.is_empty(&self.term) {
                    let text = all.text(&self.term);
                    self.conn.copy(clipboard::SELECTION, &text)?;
                }
            }
        }
        Ok(())
    }
}

pub fn main() -> i32 {
    // Frames free and allocate large buffers: keep some mappings for reuse
    // (ADR 0094's addendum).
    slate_rt::alloc_impl::keep_freed(16 << 20);
    let files = match slate_strata::session::load_fonts() {
        Ok(f) => f,
        Err(e) => {
            slate_rt::eprintln!("terminal: {e}");
            return 1;
        }
    };
    let refs: [&[u8]; 5] = core::array::from_fn(|i| files[i].as_slice());
    let Some(fonts) = Fonts::new(refs) else { return 1 };
    let italic_files = slate_strata::session::load_italics();
    let italics = render::Italics::new(&italic_files);
    match run(&fonts, &italics) {
        Ok(()) => 0,
        Err(e) => {
            slate_rt::eprintln!("terminal: {e}");
            1
        }
    }
}

/// Ask Strata to resize the window in whole cells (ADR 0102's third
/// addendum): the padding, then cells, in logical pixels.
fn steps(conn: &mut Connection, win: &Window, m: &Metrics) -> Result<(), String> {
    conn.set_steps(win, (2.0 * render::PAD_X, 2.0 * render::PAD_Y), (m.cell_w / m.scale, m.line_h / m.scale))
}

fn run(fonts: &Fonts<'_>, italics: &render::Italics<'_>) -> Result<(), String> {
    let home = slate_rt::env::var(b"HOME").map(|h| String::from(lossy(&h))).unwrap_or_default();
    let mut conn = Connection::connect()?;
    let win = conn.create("terminal", Some("~"))?;
    // 80 x 24 cells, and no fewer than 40 x 10 (logical pixels: the cells
    // at scale 1 and the padding round them; ADR 0102).
    let cells = |cols: f32, rows: f32| {
        ((2.0 * render::PAD_X + cols * render::CELL_W) as u32, (2.0 * render::PAD_Y + rows * render::LINE) as u32)
    };
    conn.set_hints(&win, cells(40.0, 10.0), cells(80.0, 24.0))?;
    // The size asked for arrives as a configure, in the loop.
    let (master, slave) = term::open_pty().map_err(|e| alloc::format!("opening a pseudo-terminal: {e}"))?;
    // Writes that would block wait in the outbox instead.
    if let Ok(flags) = process::fcntl(master, process::F_GETFL, 0) {
        let _ = process::fcntl(master, process::F_SETFL, flags | fs::O_NONBLOCK as usize);
    }
    let metrics = Metrics::new(fonts, win.scale);
    steps(&mut conn, &win, &metrics)?;
    let (cols, rows) = metrics.grid(win.width, win.height);
    let mut term = Term::new(cols, rows);
    term.set_scrollback(SCROLLBACK);
    let mut s = Session {
        conn,
        win,
        fonts,
        italics,
        metrics,
        term,
        master,
        cache: GlyphCache::new(),
        canvas: None,
        view: 0,
        selection: None,
        selecting: false,
        last_click: (i64::MIN / 2, Point { line: 0, col: 0 }, 0),
        theme: {
            let s = Settings::load();
            Theme::pick(s.theme, s.high_contrast)
        },
        settings_stamp: settings::stamp(),
        out: Outbox::default(),
        menu: None,
        held: None,
        reported: None,
    };
    s.fit();
    let shell = start_shell(&slave, &s.theme)?;
    // The window's login record (ADR 0143), until the window goes.
    let _record = Record::login(&slave, shell);
    let mut typed_at = i64::MIN / 2;
    let mut shown = (String::new(), String::new(), 0);
    let mut last_title = 0i64;
    let mut last_settings = now_ms();
    let mut dirty = true;
    loop {
        let now = now_ms();
        if now - last_settings >= SETTINGS_MS {
            last_settings = now;
            dirty |= s.follow_settings();
        }
        // The title follows the foreground program (checked twice a second).
        if now - last_title >= 500 {
            last_title = now;
            let t = title(master, shell, &home);
            if t != shown {
                s.conn.set_title(&s.win, &t.0, Some(&t.1), t.2)?;
                shown = t;
            }
        }
        let typing = now - typed_at < TYPING_MS;
        if dirty {
            s.draw(typing)?;
            dirty = false;
        }
        let wake = if typing { (typed_at + TYPING_MS - now).max(1) } else { 500 };
        let master_events = if s.out.is_empty() { io::POLLIN } else { io::POLLIN | io::POLLOUT };
        let mut fds = [
            io::PollFd { fd: s.conn.fd(), events: io::POLLIN, revents: 0 },
            io::PollFd { fd: master, events: master_events, revents: 0 },
        ];
        let _ = io::poll(&mut fds, wake as i32);
        if typing && now_ms() - typed_at >= TYPING_MS {
            dirty = true;
        }
        if fds[1].revents & io::POLLOUT != 0 {
            s.flush();
        }
        if fds[1].revents & !io::POLLOUT != 0 {
            let mut buf = alloc::vec![0u8; 65536];
            match io::read(master, &mut buf) {
                Err(Errno::EAGAIN | Errno::EINTR) => {}
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    s.term.feed(&buf[..n]);
                    let reply = s.term.take_responses();
                    if !reply.is_empty() {
                        s.send(&reply);
                    }
                    // New output returns to the bottom.
                    s.view = 0;
                    dirty = true;
                }
            }
        }
        if fds[0].revents != 0 {
            s.conn.read()?;
            for e in s.conn.take_events() {
                match e {
                    Event::Configure { .. } => {
                        if s.win.configure(&e) {
                            s.fit();
                        }
                        dirty = true;
                    }
                    Event::Key { code, .. } if let Some((mut m, _)) = s.menu => {
                        match m.key(code) {
                            Outcome::Open => s.menu = Some((m, true)),
                            Outcome::Closed => s.menu = None,
                            Outcome::Chose(item) => {
                                s.menu = None;
                                s.act(item)?;
                            }
                        }
                        dirty = true;
                    }
                    Event::Key { code, mods, .. } if let Some(l) = keys::local(code, mods) => {
                        s.local(l)?;
                        dirty = true;
                    }
                    Event::Key { code, ch, mods, .. } => {
                        let bytes = keys::encode(code, char::from_u32(ch).filter(|_| ch != 0), mods, s.term.app_cursor);
                        if !bytes.is_empty() {
                            s.send(&bytes);
                            typed_at = now_ms();
                            s.view = 0;
                            dirty = true;
                        }
                    }
                    Event::Paste { text, .. } => {
                        let bytes = keys::paste(&text, s.term.bracketed_paste);
                        s.send(&bytes);
                        s.view = 0;
                        dirty = true;
                    }
                    // Files dropped on the window type their paths (ADR 0156).
                    Event::Drop { paths, .. } => {
                        let bytes = keys::paste(&keys::dropped(&paths), s.term.bracketed_paste);
                        s.send(&bytes);
                        s.view = 0;
                        dirty = true;
                    }
                    Event::Pointer { kind, button, x, y, mods, .. } => dirty |= s.pointer(kind, button, x, y, mods)?,
                    // Taken by the client library itself.
                    Event::Release { .. } => {}
                    Event::Scroll { lines, x, y, mods, .. } if s.menu.is_none() && s.reporting(mods) => {
                        for _ in 0..lines.unsigned_abs() {
                            s.reported = None;
                            s.report(Action::Wheel { up: lines < 0 }, x, y, mods);
                        }
                    }
                    Event::Scroll { lines, .. } if s.term.alternate() => {
                        // Full-screen programs have no scrollback: the
                        // wheel moves them with the arrow keys.
                        let code = if lines < 0 { KEY_UP } else { KEY_DOWN };
                        for _ in 0..lines.unsigned_abs() as i64 * WHEEL_LINES {
                            let bytes = keys::encode(code, None, 0, s.term.app_cursor);
                            s.send(&bytes);
                        }
                    }
                    Event::Scroll { lines, .. } => {
                        s.scroll(i64::from(lines) * WHEEL_LINES);
                        dirty = true;
                    }
                    Event::Close { .. } => {
                        let _ = process::kill(-shell, SIGHUP);
                        let _ = process::kill(shell, SIGHUP);
                        return Ok(());
                    }
                }
            }
        }
    }
    // The shell ended: close the window.
    let _ = process::wait(shell, 0);
    s.conn.destroy(s.win)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_greys() {
        assert_eq!(sgr(slate_ui::graphite::Palette::GRAPHITE.muted), "38;2;133;131;126");
        assert_eq!(sgr(slate_ui::graphite::Palette::DAY.inactive), "38;2;140;139;139");
    }
}
