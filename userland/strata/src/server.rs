// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strata's side of the client protocol (ADR 0037, `strata-proto`): it
//! listens on the abstract socket `strata-<uid>`, accepts apps, turns their
//! requests into windows in the window manager, keeps their buffers, and
//! sends them sizes, focus, keys, pointer events and close requests. It
//! keeps the clipboards, which only the app with the focused window may
//! set or read (ADR 0038).
//!
//! A client's domain comes from the socket's peer credentials and
//! `/proc/<pid>/status`, never from the client itself.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::mem::Mapping;
use slate_rt::{fs, io, lossy, net};
use slate_ui::icon::Icon;
use strata_proto::{Event, Next, Request};

use crate::wm::{WinId, Wm};

/// A client's window.
#[derive(Debug)]
pub struct ClientWindow {
    pub cwin: u32,
    pub id: WinId,
    /// The client's two buffers, and the one shown (ADR 0039).
    buffers: [Option<Buffer>; 2],
    front: Option<u8>,
    /// The last size and focus sent.
    sent: Option<(u32, u32, bool)>,
    /// When the person asked to close it (ms), if they did.
    close_asked: Option<i64>,
    /// Its app keeps the screen from locking by itself (a video playing).
    pub inhibit: bool,
}

/// A window's pixels, mapped from the client's shared memory.
#[derive(Debug)]
pub struct Buffer {
    map: Mapping,
    pub width: u32,
    pub height: u32,
    /// Which buffer this is, never reused (for what keeps a buffer's
    /// pixels by where they are: the card's 2D images).
    pub serial: u64,
}

/// The next buffer's serial.
static SERIAL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

impl Buffer {
    pub fn pixels(&mut self) -> &mut [u32] {
        self.map.words_mut()
    }
}

#[derive(Debug)]
pub struct Client {
    pub fd: i32,
    pub pid: i32,
    pub linux: bool,
    /// It runs inside a Linux runtime's sandbox (ADR 0038).
    pub sandboxed: bool,
    inbuf: Vec<u8>,
    fds: VecDeque<i32>,
    pub windows: Vec<ClientWindow>,
    /// When it last sent anything (ms on the monotonic clock).
    last_heard: i64,
}

/// A field of /proc/<pid>/status.
fn status_field(pid: i32, field: &str) -> Option<String> {
    let status = fs::read_file(format!("/proc/{pid}/status").as_bytes()).ok()?;
    let text = String::from(lossy(&status));
    text.lines().find_map(|l| l.strip_prefix(field).and_then(|r| r.strip_prefix(':')).map(|v| String::from(v.trim())))
}

/// Whether process `pid` runs in the Linux domain (`Domain:` in its
/// status; absent outside Slate).
fn linux_domain(pid: i32) -> bool {
    status_field(pid, "Domain").as_deref() == Some("linux")
}

/// Whether `pid` runs inside a Linux runtime's sandbox (ADR 0038): in
/// the Linux domain, with a root of its own (slate-linux-app makes the
/// runtime its programs' root), as `/proc/<pid>/root` shows.
fn sandboxed(pid: i32) -> bool {
    linux_domain(pid) && fs::readlink(format!("/proc/{pid}/root").as_bytes()).is_ok_and(|r| r != b"/")
}

/// Whether `pid` is `ancestor` or one of its descendants (following
/// `PPid:`).
fn descends_from(pid: i32, ancestor: i32) -> bool {
    let mut p = pid;
    for _ in 0..64 {
        if p == ancestor {
            return true;
        }
        match status_field(p, "PPid").and_then(|v| v.parse::<i32>().ok()) {
            Some(parent) if parent > 0 && parent != p => p = parent,
            _ => return false,
        }
    }
    false
}

/// How long an app may say nothing after being asked to close before a
/// second request closes its window anyway (ms).
pub const UNRESPONSIVE_MS: i64 = 5000;

fn now_ms() -> i64 {
    (slate_rt::time::monotonic_ns() / 1_000_000) as i64
}

/// What clients changed: the windows (added, removed, retitled), or
/// only some windows' contents (and where, in the buffer's pixels).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub windows: bool,
    pub contents: Vec<(WinId, slate_ui::Rect)>,
}

impl Changes {
    fn merge(&mut self, o: Changes) {
        self.windows |= o.windows;
        self.contents.extend(o.contents);
    }

    fn windows() -> Changes {
        Changes { windows: true, contents: Vec::new() }
    }

    pub fn any(&self) -> bool {
        self.windows || !self.contents.is_empty()
    }
}

#[derive(Debug)]
pub struct Server {
    listen: i32,
    pub name: Vec<u8>,
    pub clients: Vec<Client>,
    /// The clipboard and the selection (`strata_proto::clipboard`).
    clipboards: [String; 2],
    /// The modifiers held, sent with pointer and wheel events (the session
    /// keeps it up to date).
    pub mods: u8,
    /// The apps' programs and glyphs (`exec`, `icon`): a window's title
    /// bar shows its program's (ADR 0124).
    pub icons: Vec<(String, Icon)>,
    /// Files an app is dragging out of its window (ADR 0156): the window
    /// and the paths, until the session sees the button come up.
    pub drag: Option<(WinId, Vec<String>)>,
}

impl Server {
    /// Listen on the abstract socket `name`.
    pub fn listen(name: &[u8]) -> Result<Server, String> {
        let listen = net::listen(name).map_err(|e| format!("listening on @{}: {e}", lossy(name)))?;
        Ok(Server {
            listen,
            name: name.to_vec(),
            clients: Vec::new(),
            clipboards: Default::default(),
            mods: 0,
            icons: Vec::new(),
            drag: None,
        })
    }

    /// The descriptors to wait on: the listening socket, then the clients.
    pub fn poll_fds(&self) -> Vec<io::PollFd> {
        core::iter::once(self.listen)
            .chain(self.clients.iter().map(|c| c.fd))
            .map(|fd| io::PollFd { fd, events: io::POLLIN, revents: 0 })
            .collect()
    }

    /// Handle what `ready` (from [`Server::poll_fds`]) says has arrived.
    /// Returns whether the screen needs drawing.
    pub fn handle(&mut self, ready: &[io::PollFd], wm: &mut Wm) -> Changes {
        let mut changed = Changes::default();
        if ready.first().is_some_and(|p| p.revents != 0)
            && let Ok(fd) = net::accept(self.listen)
        {
            let pid = net::peer_cred(fd).map(|c| c.0).unwrap_or(0);
            self.clients.push(Client {
                fd,
                pid,
                linux: linux_domain(pid),
                sandboxed: sandboxed(pid),
                inbuf: Vec::new(),
                fds: VecDeque::new(),
                windows: Vec::new(),
                last_heard: now_ms(),
            });
        }
        let mut gone = Vec::new();
        for (i, p) in ready.iter().skip(1).enumerate() {
            if p.revents == 0 || i >= self.clients.len() {
                continue;
            }
            match self.read(i, wm) {
                Ok(c) => changed.merge(c),
                Err(e) => {
                    slate_rt::eprintln!("strata: client {}: {e}", self.clients[i].pid);
                    gone.push(i);
                }
            }
        }
        for i in gone.into_iter().rev() {
            let c = self.clients.remove(i);
            for w in &c.windows {
                wm.remove(w.id);
            }
            for fd in c.fds {
                let _ = io::close(fd);
            }
            let _ = io::close(c.fd);
            changed.windows = true;
        }
        changed
    }

    /// Read from client `i` and carry out its requests.
    fn read(&mut self, i: usize, wm: &mut Wm) -> Result<Changes, String> {
        let mut buf = [0u8; 4096];
        let (n, fds) = net::recv_fds(self.clients[i].fd, &mut buf).map_err(|e| format!("{e}"))?;
        if n == 0 && fds.is_empty() {
            return Err("disconnected".into());
        }
        let c = &mut self.clients[i];
        c.last_heard = now_ms();
        c.fds.extend(fds);
        c.inbuf.extend_from_slice(&buf[..n]);
        let mut changed = Changes::default();
        loop {
            let r = match strata_proto::next_request(&mut self.clients[i].inbuf) {
                Next::Message(r) => r,
                Next::Incomplete => return Ok(changed),
                Next::Broken => return Err("unreadable request".into()),
            };
            changed.merge(self.request(i, r, wm)?);
        }
    }

    fn request(&mut self, i: usize, r: Request, wm: &mut Wm) -> Result<Changes, String> {
        let focused = wm.focused().map(|w| w.id);
        let c = &mut self.clients[i];
        let path = |p: String| if p.is_empty() { None } else { Some(p) };
        match r {
            Request::Hello { .. } => Ok(Changes::default()),
            Request::Create { win, app, path: p } => {
                if c.windows.iter().any(|w| w.cwin == win) {
                    return Err(format!("window {win} exists"));
                }
                let id = wm.add(&app, path(p).as_deref(), c.linux);
                // The glyph of the app whose program the client runs, as
                // the kernel names it (never what the client says).
                let exe = fs::readlink(format!("/proc/{}/exe", c.pid).as_bytes()).ok();
                let icon =
                    exe.as_ref().and_then(|e| self.icons.iter().find(|(x, _)| x.as_bytes() == *e).map(|(_, i)| *i));
                let program = exe.map(|e| String::from(lossy(e.rsplit(|&b| b == b'/').next().unwrap_or(&e))));
                if let Some(w) = wm.get_mut(id) {
                    w.sandboxed = c.sandboxed;
                    w.icon = icon;
                    w.program = program;
                }
                slate_rt::eprintln!(
                    "strata: window {id} \"{app}\" from pid {} ({})",
                    c.pid,
                    match (c.linux, c.sandboxed) {
                        (true, true) => "linux, sandboxed",
                        (true, false) => "linux",
                        _ => "slate",
                    }
                );
                c.windows.push(ClientWindow {
                    cwin: win,
                    id,
                    buffers: [None, None],
                    front: None,
                    sent: None,
                    close_asked: None,
                    inhibit: false,
                });
                Ok(Changes::windows())
            }
            Request::Title { win, app, path: p, pid } => {
                let Some(w) = c.windows.iter().find(|w| w.cwin == win) else { return Ok(Changes::default()) };
                // The domain shown is the named process's if it is the
                // client's own descendant, else the client's.
                let named = pid as i32;
                let linux = if named > 0 && descends_from(named, c.pid) { linux_domain(named) } else { c.linux };
                if let Some(mw) = wm.get_mut(w.id) {
                    // Logged when the program shown or its domain changes.
                    if mw.linux != linux || mw.app != app {
                        slate_rt::eprintln!(
                            "strata: window {} shows \"{app}\" ({})",
                            w.id,
                            if linux { "linux" } else { "slate" }
                        );
                    }
                    mw.app = app;
                    mw.path = path(p);
                    mw.linux = linux;
                }
                Ok(Changes::windows())
            }
            Request::Buffer { win, width, height, index } => {
                let fd = c.fds.pop_front().ok_or("a buffer without its descriptor")?;
                let len = (width as usize).saturating_mul(height as usize).saturating_mul(4);
                let map = if len == 0 || width > 16384 || height > 16384 {
                    Err(slate_rt::Errno::EINVAL)
                } else {
                    Mapping::shared(fd, len, 0)
                };
                let _ = io::close(fd);
                let map = map.map_err(|e| format!("mapping its buffer: {e}"))?;
                if let Some(w) = c.windows.iter_mut().find(|w| w.cwin == win)
                    && let Some(slot) = w.buffers.get_mut(usize::from(index))
                {
                    let serial = SERIAL.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    *slot = Some(Buffer { map, width, height, serial });
                }
                Ok(Changes::default())
            }
            // Show buffer `index`; the one shown before goes back to the
            // client (Strata reads buffers only while drawing, not now).
            Request::Damage { win, index, x, y, width, height } => {
                let Some(w) = c.windows.iter_mut().find(|w| w.cwin == win) else { return Ok(Changes::default()) };
                if w.buffers.get(usize::from(index)).is_none_or(Option::is_none) {
                    return Ok(Changes::default());
                }
                let old = w.front.replace(index);
                let id = w.id;
                if let Some(old) = old.filter(|o| *o != index) {
                    self.send(i, &Event::Release { win, index: old });
                }
                let r = slate_ui::Rect::new(x as i32, y as i32, width.min(16384) as i32, height.min(16384) as i32);
                Ok(Changes { windows: false, contents: alloc::vec![(id, r)] })
            }
            Request::Destroy { win } => {
                let Some(at) = c.windows.iter().position(|w| w.cwin == win) else { return Ok(Changes::default()) };
                let w = c.windows.remove(at);
                wm.remove(w.id);
                Ok(Changes::windows())
            }
            Request::Copy { which, text } => {
                let ours = c.windows.iter().any(|w| Some(w.id) == focused);
                if let Some(board) = self.clipboards.get_mut(usize::from(which)).filter(|_| ours) {
                    *board = text;
                }
                Ok(Changes::default())
            }
            Request::Hints { win, min_width, min_height, width, height } => {
                let Some(w) = c.windows.iter().find(|w| w.cwin == win) else { return Ok(Changes::default()) };
                // The app speaks of its content; the frame adds the title bar
                // and the border (draw::content).
                let f = |v: u32, extra: f32| if v == 0 { 0.0 } else { v.min(16384) as f32 + extra };
                let (ew, eh) = (2.0, wm.extra_h());
                wm.hints(w.id, (f(min_width, ew), f(min_height, eh)), (f(width, ew), f(height, eh)));
                // Where it went, for the scenarios that point into it.
                if let Some(a) = wm.frame(w.id) {
                    slate_rt::eprintln!("strata: window {} placed at {} {} {} {}", w.id, a.x, a.y, a.w, a.h);
                }
                Ok(Changes::windows())
            }
            Request::Steps { win, base_width, base_height, width, height } => {
                let Some(w) = c.windows.iter().find(|w| w.cwin == win) else { return Ok(Changes::default()) };
                let f = |v: u32| v.min(1_000_000) as f32 / 100.0;
                wm.steps(w.id, (f(base_width), f(base_height)), (f(width), f(height)));
                if let (Some((cols, rows)), Some(a)) = (wm.size_in_steps(w.id), wm.frame(w.id)) {
                    slate_rt::eprintln!(
                        "strata: window {} resizes in steps, {cols} x {rows} now, its frame at {} {} {} {}",
                        w.id,
                        a.x,
                        a.y,
                        a.w,
                        a.h
                    );
                }
                Ok(Changes::windows())
            }
            Request::Inhibit { win, on } => {
                if let Some(w) = c.windows.iter_mut().find(|w| w.cwin == win)
                    && w.inhibit != on
                {
                    w.inhibit = on;
                    slate_rt::eprintln!(
                        "strata: window {} {} the idle lock",
                        w.id,
                        if on { "holds off" } else { "no longer holds off" }
                    );
                }
                Ok(Changes::default())
            }
            Request::Paste { win, which } => {
                let ours = c.windows.iter().any(|w| w.cwin == win && Some(w.id) == focused);
                if let Some(board) = self.clipboards.get(usize::from(which)).filter(|_| ours) {
                    let e = Event::Paste { win, which, text: board.clone() };
                    self.send(i, &e);
                }
                Ok(Changes::default())
            }
            // Only a Slate app's focused window, which has the button held,
            // drags; a Linux program can't have Strata move files for it.
            Request::Drag { win, paths } => {
                let w = c.windows.iter().find(|w| w.cwin == win && Some(w.id) == focused);
                match w {
                    Some(w) if !c.linux => {
                        let paths: Vec<String> =
                            paths.lines().filter(|l| l.starts_with('/')).map(String::from).collect();
                        slate_rt::eprintln!("strata: window {} drags {} files", w.id, paths.len());
                        self.drag = Some((w.id, paths));
                    }
                    _ => slate_rt::eprintln!("strata: a drag from pid {} refused", c.pid),
                }
                Ok(Changes::default())
            }
        }
    }

    /// The client and window index owning `id`.
    fn find(&self, id: WinId) -> Option<(usize, usize)> {
        self.clients.iter().enumerate().find_map(|(ci, c)| c.windows.iter().position(|w| w.id == id).map(|wi| (ci, wi)))
    }

    fn send(&mut self, ci: usize, e: &Event) {
        // A client that does not read is dropped at its next request.
        let _ = io::write_all(self.clients[ci].fd, &e.encode());
    }

    /// Tell every window whose size or focus changed: `sizes` holds each
    /// visible window's content size in device pixels.
    pub fn configure(&mut self, sizes: &[(WinId, u32, u32)], focused: Option<WinId>, scale: f32) {
        for &(id, w, h) in sizes {
            let Some((ci, wi)) = self.find(id) else { continue };
            let now = (w, h, focused == Some(id));
            let cw = &mut self.clients[ci].windows[wi];
            if cw.sent == Some(now) {
                continue;
            }
            cw.sent = Some(now);
            let e =
                Event::Configure { win: cw.cwin, width: w, height: h, scale: (scale * 100.0) as u32, focused: now.2 };
            self.send(ci, &e);
        }
        // Windows no longer focused (on other workspaces) hear of it too.
        let unfocus: Vec<(usize, usize)> = self
            .clients
            .iter()
            .enumerate()
            .flat_map(|(ci, c)| c.windows.iter().enumerate().map(move |(wi, w)| (ci, wi, w)))
            .filter(|(_, _, w)| w.sent.is_some_and(|s| s.2) && Some(w.id) != focused)
            .map(|(ci, wi, _)| (ci, wi))
            .collect();
        for (ci, wi) in unfocus {
            let cw = &mut self.clients[ci].windows[wi];
            let Some((w, h, _)) = cw.sent else { continue };
            cw.sent = Some((w, h, false));
            let e =
                Event::Configure { win: cw.cwin, width: w, height: h, scale: (scale * 100.0) as u32, focused: false };
            self.send(ci, &e);
        }
    }

    /// Pass a key to the window's client.
    pub fn key(&mut self, id: WinId, code: u16, ch: Option<char>, mods: u8) {
        if let Some((ci, wi)) = self.find(id) {
            let e = Event::Key { win: self.clients[ci].windows[wi].cwin, code, ch: ch.map_or(0, u32::from), mods };
            self.send(ci, &e);
        }
    }

    /// Pass a pointer event (window device pixels) to the window's client.
    pub fn pointer(&mut self, id: WinId, kind: strata_proto::PointerKind, button: u8, x: i32, y: i32) {
        if let Some((ci, wi)) = self.find(id) {
            let mods = self.mods;
            let e = Event::Pointer { win: self.clients[ci].windows[wi].cwin, kind, button, x, y, mods };
            self.send(ci, &e);
        }
    }

    /// Pass a turn of the wheel to the window's client.
    pub fn scroll(&mut self, id: WinId, x: i32, y: i32, lines: i32) {
        if let Some((ci, wi)) = self.find(id) {
            let mods = self.mods;
            let e = Event::Scroll { win: self.clients[ci].windows[wi].cwin, x, y, lines, mods };
            self.send(ci, &e);
        }
    }

    /// Files dropped on window `id` at (x, y), device pixels in its
    /// content (ADR 0156), to be copied with `copy`; never to a Linux
    /// program's. Whether it was told.
    pub fn drop_files(&mut self, id: WinId, x: i32, y: i32, paths: &[String], copy: bool) -> bool {
        let Some((ci, wi)) = self.find(id).filter(|(ci, _)| !self.clients[*ci].linux) else { return false };
        let e = Event::Drop { win: self.clients[ci].windows[wi].cwin, x, y, paths: paths.join("\n"), copy };
        self.send(ci, &e);
        true
    }

    /// The person closed window `id`: tell its client and forget it.
    /// The person asked to close window `id`: its app is asked, and the
    /// window goes when the app closes it (an app with unsaved work may
    /// ask first). Asked again when the app hasn't said anything for
    /// [`UNRESPONSIVE_MS`] since the first time, the window goes at
    /// once. True if it went (or has no app).
    pub fn close(&mut self, id: WinId, now: i64) -> bool {
        let Some((ci, wi)) = self.find(id) else { return true };
        let c = &mut self.clients[ci];
        let w = &mut c.windows[wi];
        let cwin = w.cwin;
        let stuck = w.close_asked.is_some_and(|t| now - t >= UNRESPONSIVE_MS && c.last_heard < t);
        w.close_asked.get_or_insert(now);
        self.send(ci, &Event::Close { win: cwin });
        if stuck {
            slate_rt::eprintln!("strata: window {id} isn't answering: closed");
            self.clients[ci].windows.remove(wi);
        }
        stuck
    }

    /// Whether a window's app keeps the screen from locking by itself.
    pub fn inhibited(&self) -> bool {
        self.clients.iter().any(|c| c.windows.iter().any(|w| w.inhibit))
    }

    /// The buffer of window `id`, if its client gave one.
    pub fn buffer(&mut self, id: WinId) -> Option<&mut Buffer> {
        let (ci, wi) = self.find(id)?;
        let w = &mut self.clients[ci].windows[wi];
        let front = usize::from(w.front?);
        w.buffers[front].as_mut()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        for c in &self.clients {
            let _ = io::close(c.fd);
        }
        let _ = io::close(self.listen);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slate_strata_client::Connection;
    use slate_ui::{Canvas, Color};

    /// A client opens a window, learns its size, presents pixels Strata
    /// can read, hears of a close, and its window goes when it leaves.
    #[test]
    fn a_client_and_its_window() {
        let name = format!("strata-test-{}", std::process::id()).into_bytes();
        let mut server = Server::listen(&name).unwrap();
        let mut wm = Wm::new(1280.0, 800.0);
        let client_name = name.clone();
        let client = std::thread::spawn(move || {
            let mut conn = Connection::connect_to(&client_name).unwrap();
            let mut win = conn.create("demo", Some("~/here")).unwrap();
            assert_eq!((win.width, win.height, win.focused), (300, 200, true));
            let canvas = Canvas::new(win.width as i32, win.height as i32, Color::rgb(0xAB1234));
            // Holding off the idle lock, before the pixels come.
            conn.inhibit(&win, true).unwrap();
            conn.present(&mut win, &canvas).unwrap();
            // Wait for the close.
            loop {
                if conn.poll(1000).unwrap().iter().any(|e| matches!(e, slate_strata_client::Event::Close { .. })) {
                    return;
                }
            }
        });
        let mut pixel = None;
        let mut closed = false;
        for _ in 0..500 {
            let mut fds = server.poll_fds();
            let _ = io::poll(&mut fds, 10);
            server.handle(&fds, &mut wm);
            if let Some(w) = wm.focused() {
                let id = w.id;
                assert_eq!((w.app.as_str(), w.path.as_deref(), w.linux), ("demo", Some("~/here"), false));
                server.configure(&[(id, 300, 200)], Some(id), 1.0);
                if let Some(b) = server.buffer(id) {
                    let p = b.pixels()[300 * 199 + 299];
                    if p != 0 {
                        assert!(server.inhibited(), "held off before the pixels");
                        pixel = Some(p);
                        // Asked, not taken: the window goes with its app.
                        if !closed {
                            assert!(!server.close(id, now_ms()));
                        }
                        closed = true;
                    }
                }
            }
            if closed && client.is_finished() {
                break;
            }
        }
        client.join().unwrap();
        assert_eq!(pixel, Some(0xFFAB_1234));
        // The client has gone: its connection goes at the next poll.
        for _ in 0..50 {
            let mut fds = server.poll_fds();
            let _ = io::poll(&mut fds, 10);
            server.handle(&fds, &mut wm);
            if server.clients.is_empty() {
                break;
            }
        }
        assert!(server.clients.is_empty());
        assert!(wm.windows.is_empty());
        assert!(!server.inhibited(), "its window has gone");
    }

    /// An app that says nothing after being asked to close loses its
    /// window when asked again, later.
    #[test]
    fn a_stuck_app_is_closed_on_the_second_request() {
        let name = format!("strata-stuck-{}", std::process::id()).into_bytes();
        let mut server = Server::listen(&name).unwrap();
        let mut wm = Wm::new(1280.0, 800.0);
        let n = name.clone();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let app = std::thread::spawn(move || {
            let mut conn = Connection::connect_to(&n).unwrap();
            let _win = conn.create("stuck", None).unwrap();
            // Never reads again until told to go.
            let _ = rx.recv();
        });
        let mut id = None;
        for _ in 0..300 {
            let mut fds = server.poll_fds();
            let _ = io::poll(&mut fds, 10);
            server.handle(&fds, &mut wm);
            if let Some(w) = wm.focused() {
                id = Some(w.id);
                server.configure(&[(w.id, 300, 200)], Some(w.id), 1.0);
                break;
            }
        }
        let id = id.unwrap();
        let t = now_ms() + 1000;
        assert!(!server.close(id, t), "asked");
        assert!(!server.close(id, t + 100), "too soon to call it stuck");
        assert!(server.close(id, t + UNRESPONSIVE_MS), "stuck: gone");
        tx.send(()).unwrap();
        app.join().unwrap();
    }

    /// Only the app with the focused window sets or reads the clipboard.
    #[test]
    fn the_clipboard_follows_the_focus() {
        use slate_strata_client::clipboard::CLIPBOARD;
        let name = format!("strata-clip-{}", std::process::id()).into_bytes();
        let mut server = Server::listen(&name).unwrap();
        let mut wm = Wm::new(1280.0, 800.0);
        let n = name.clone();
        let apps = std::thread::spawn(move || {
            let pasted = |conn: &mut Connection| -> Option<String> {
                for _ in 0..30 {
                    for e in conn.poll(10).unwrap() {
                        if let slate_strata_client::Event::Paste { text, .. } = e {
                            return Some(text);
                        }
                    }
                }
                None
            };
            let mut one = Connection::connect_to(&n).unwrap();
            let w1 = one.create("one", None).unwrap();
            let mut two = Connection::connect_to(&n).unwrap();
            let w2 = two.create("two", None).unwrap();
            // "two" has the focus: its copy counts, "one"'s doesn't.
            two.copy(CLIPBOARD, "from two").unwrap();
            one.copy(CLIPBOARD, "from one").unwrap();
            one.paste(&w1, CLIPBOARD).unwrap();
            two.paste(&w2, CLIPBOARD).unwrap();
            (pasted(&mut one), pasted(&mut two))
        });
        for _ in 0..1000 {
            let mut fds = server.poll_fds();
            let _ = io::poll(&mut fds, 5);
            server.handle(&fds, &mut wm);
            let sizes: Vec<_> = wm.windows.iter().map(|w| (w.id, 300, 200)).collect();
            let focused = wm.focused().map(|w| w.id);
            server.configure(&sizes, focused, 1.0);
            if apps.is_finished() {
                break;
            }
        }
        let (one, two) = apps.join().unwrap();
        assert_eq!(one, None);
        assert_eq!(two.as_deref(), Some("from two"));
    }
}
