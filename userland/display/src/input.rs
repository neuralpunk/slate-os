// SPDX-License-Identifier: MIT OR Apache-2.0

//! Input for Slate's graphical programs: every `/dev/input/event*`
//! (keyboards, mice, tablets), read as evdev events and turned into key
//! presses with their modifiers, or slate-ui events (ADR 0033, ADR 0034,
//! ADR 0037). Keyboard layouts and key repeat are applied
//! here, since the kernel only reports key positions.
//!
//! Sources (as for the kernel's input layer, ADR 0033): event types and
//! codes, ioctl numbers and the `input_event`/`input_absinfo` layouts from
//! the UAPI `linux/input.h` and `input-event-codes.h`, used only as a
//! table of numbers; the layouts' characters from xkeyboard-config 2.43's
//! `symbols/us`, `symbols/gb` and `symbols/pc` (MIT).

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, io, lossy};
use slate_ui::ui::{Event, Key};

// Event types and codes (input-event-codes.h).
const EV_SYN: u16 = 0x00;
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;
const EV_ABS: u16 = 0x03;
const SYN_REPORT: u16 = 0;
const REL_X: u16 = 0x00;
const REL_Y: u16 = 0x01;
const ABS_X: u16 = 0x00;
const ABS_Y: u16 = 0x01;
const REL_WHEEL: u16 = 0x08;
const BTN_LEFT: u16 = 0x110;
const BTN_RIGHT: u16 = 0x111;
const BTN_MIDDLE: u16 = 0x112;
const BTN_TOUCH: u16 = 0x14a;

pub const KEY_ESC: u16 = 1;
pub const KEY_BACKSPACE: u16 = 14;
pub const KEY_TAB: u16 = 15;
pub const KEY_ENTER: u16 = 28;
const KEY_LEFTCTRL: u16 = 29;
const KEY_LEFTSHIFT: u16 = 42;
const KEY_RIGHTSHIFT: u16 = 54;
const KEY_LEFTALT: u16 = 56;
pub const KEY_SPACE: u16 = 57;
const KEY_CAPSLOCK: u16 = 58;
pub const KEY_KPENTER: u16 = 96;
const KEY_RIGHTCTRL: u16 = 97;
const KEY_RIGHTALT: u16 = 100;
/// The logo ("super") keys: pressed and released alone, they come out as
/// a key of their own (see [`Input::Key`]).
pub const KEY_LEFTMETA: u16 = 125;
pub const KEY_RIGHTMETA: u16 = 126;
/// The keys 1 to 4 and Q, E (Strata's shortcuts).
pub const KEY_1: u16 = 2;
pub const KEY_4: u16 = 5;
pub const KEY_Q: u16 = 16;
pub const KEY_E: u16 = 18;
/// L (super + L locks, ADR 0039).
pub const KEY_L: u16 = 38;
/// S (super + S opens quick settings, ADR 0186).
pub const KEY_S: u16 = 31;
pub const KEY_UP: u16 = 103;
pub const KEY_LEFT: u16 = 105;
pub const KEY_RIGHT: u16 = 106;
pub const KEY_DOWN: u16 = 108;
pub const KEY_HOME: u16 = 102;
pub const KEY_END: u16 = 107;
pub const KEY_DELETE: u16 = 111;
pub const KEY_PAGEUP: u16 = 104;
pub const KEY_PAGEDOWN: u16 = 109;
/// A, F2, F10 and the menu key (the desktop's select all, rename and
/// menu, ADR 0156).
pub const KEY_A: u16 = 30;
pub const KEY_F2: u16 = 60;
pub const KEY_F10: u16 = 68;
pub const KEY_COMPOSE: u16 = 127;

/// A keyboard layout (ADR 0034, ADR 0117: the installer's choice); the
/// tables are shared with the kernel console (`slate_term::keymap`).
pub use slate_term::keymap::Layout;

/// The system's layout: the one /etc/slate/keyboard names (the
/// installer's choice, ADR 0117), US without one.
pub fn system_layout() -> Layout {
    let name = fs::read_file(b"/etc/slate/keyboard").unwrap_or_default();
    Layout::named(lossy(&name).trim())
}

/// The modifier keys held.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mods {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub caps: bool,
    /// The logo ("super") key.
    pub logo: bool,
    /// AltGr (the right Alt key, in layouts that have it).
    pub altgr: bool,
}

/// What happened, for a program that wants every key with its modifiers
/// (Strata, its terminal).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Input {
    /// A key press, or its repeat: the evdev code, what it means to the
    /// installer (none with Ctrl, Alt or the logo key), the character it
    /// types under the layout whatever the modifiers, and the modifiers.
    /// A logo key pressed and released with nothing else pressed between
    /// (no key, no button, no wheel) is a press of its own code, at its
    /// release, with no meaning and no character: Strata opens its
    /// Applications menu for it.
    Key {
        code: u16,
        key: Option<Key>,
        ch: Option<char>,
        mods: Mods,
    },
    Pointer(Event),
    /// The middle (2) or right (3) button, pressed or released, where the
    /// pointer is.
    Button {
        button: u8,
        down: bool,
        x: f32,
        y: f32,
    },
    /// The wheel turned: `lines` < 0 is up (away from the person).
    Wheel {
        lines: i32,
        x: f32,
        y: f32,
    },
}

/// The character `code` types, with Shift and Caps Lock applied.
pub fn character(layout: Layout, mods: Mods, code: u16) -> Option<char> {
    slate_term::keymap::character(layout, code, mods.shift, mods.caps, mods.altgr)
}

/// What a key press means to the installer. With ctrl, a letter is a
/// shortcut's (`Key::Char` with the modifiers saying ctrl); alt and the
/// logo key leave it alone.
pub fn translate(layout: Layout, mods: Mods, code: u16) -> Option<Key> {
    Some(match code {
        KEY_TAB if mods.shift => Key::BackTab,
        KEY_TAB => Key::Tab,
        KEY_ENTER | KEY_KPENTER => Key::Enter,
        KEY_ESC => Key::Escape,
        KEY_BACKSPACE => Key::Backspace,
        KEY_DELETE => Key::Delete,
        KEY_SPACE => Key::Space,
        KEY_UP => Key::Up,
        KEY_DOWN => Key::Down,
        KEY_LEFT => Key::Left,
        KEY_RIGHT => Key::Right,
        KEY_HOME => Key::Home,
        KEY_END => Key::End,
        _ if mods.alt || mods.logo => return None,
        // Caps Lock shifts letters only.
        _ => Key::Char(character(layout, mods, code)?),
    })
}

/// The modifiers slate-ui's events carry.
pub fn ui_mods(m: Mods) -> slate_ui::ui::Mods {
    slate_ui::ui::Mods { shift: m.shift, ctrl: m.ctrl }
}

fn is_modifier(code: u16) -> bool {
    matches!(
        code,
        KEY_LEFTSHIFT
            | KEY_RIGHTSHIFT
            | KEY_LEFTCTRL
            | KEY_RIGHTCTRL
            | KEY_LEFTALT
            | KEY_RIGHTALT
            | KEY_CAPSLOCK
            | KEY_LEFTMETA
            | KEY_RIGHTMETA
    )
}

/// EVIOCGBIT(ev, len): `_IOC(_IOC_READ, 'E', 0x20 + ev, len)`.
const fn eviocgbit(ev: u16, len: usize) -> u32 {
    0x8000_0000 | ((len as u32) << 16) | 0x4500 | (0x20 + ev as u32)
}

/// EVIOCGABS(abs): `_IOR('E', 0x40 + abs, struct input_absinfo)`.
const fn eviocgabs(abs: u16) -> u32 {
    0x8000_0000 | (24 << 16) | 0x4500 | (0x40 + abs as u32)
}

/// EVIOCSCLOCKID: `_IOW('E', 0xa0, int)`, the clock of the events'
/// timestamps; CLOCK_MONOTONIC (clock_gettime(2)) here.
const EVIOCSCLOCKID: u32 = 0x4004_45a0;
const CLOCK_MONOTONIC: i32 = 1;

/// One open event device.
#[derive(Debug)]
struct Device {
    name: Vec<u8>,
    fd: i32,
    /// An absolute pointer's X and Y ranges.
    abs: Option<[(i32, i32); 2]>,
}

impl Device {
    /// Open an event device, through seatd when there is a seat.
    fn open(name: &[u8], seat: Option<&mut crate::seat::Seat>) -> Option<Device> {
        let mut path = b"/dev/input/".to_vec();
        path.extend_from_slice(name);
        let fd = match seat {
            Some(s) => s.open_device(&path).ok()?,
            None => fs::open(&path, fs::O_RDONLY | fs::O_NONBLOCK | fs::O_CLOEXEC, 0).ok()?,
        };
        let mut types = [0u8; 4];
        let _ = io::ioctl(fd, eviocgbit(0, types.len()), types.as_mut_ptr() as usize);
        // Timestamps on the monotonic clock, to compare with now (latency).
        let clock = CLOCK_MONOTONIC;
        let _ = io::ioctl(fd, EVIOCSCLOCKID, &raw const clock as usize);
        let abs = if types[0] & (1 << EV_ABS) != 0 {
            let range = |axis: u16| {
                // struct input_absinfo: value, minimum, maximum, fuzz,
                // flat, resolution.
                let mut info = [0i32; 6];
                io::ioctl(fd, eviocgabs(axis), info.as_mut_ptr() as usize).ok().map(|_| (info[1], info[2]))
            };
            range(ABS_X).zip(range(ABS_Y)).map(|(x, y)| [x, y])
        } else {
            None
        };
        Some(Device { name: name.to_vec(), fd, abs })
    }
}

/// Every input device, and the state their events build up.
/// How the pointer feels (ADR 0186).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Feel {
    /// From -2 (slowest) to 2 (fastest); 0 moves as the mouse reports.
    pub speed: i8,
    /// The wheel moves the content, not the view.
    pub natural: bool,
    /// The mouse's buttons swapped.
    pub left_handed: bool,
}

impl Feel {
    /// What relative motion is multiplied by: half to twice, in five
    /// steps of a square root of two.
    pub fn factor(&self) -> f32 {
        match self.speed.clamp(-2, 2) {
            -2 => 0.5,
            -1 => 0.707,
            0 => 1.0,
            1 => 1.414,
            _ => 2.0,
        }
    }
}

#[derive(Debug)]
pub struct Inputs {
    devices: Vec<Device>,
    pub layout: Layout,
    /// A dead key waiting for the next key (ADR 0117).
    dead: slate_term::keymap::Composer,
    mods: Mods,
    shifts: [bool; 2],
    /// The pointer, in screen pixels, and the screen's size.
    pub pointer: (f32, f32),
    screen: (f32, f32),
    /// The displays' rectangles in the screen (x, y, w, h): the pointer
    /// stays on one of them (ADR 0170). Empty: the whole screen.
    areas: Vec<(f32, f32, f32, f32)>,
    /// A display was plugged in, taken out or changed (a DRM HOTPLUG
    /// uevent): the program reads its displays again and clears this.
    pub displays_changed: bool,
    /// Some pointing device has moved.
    pub pointer_seen: bool,
    /// How the person likes the pointer (ADR 0186): its speed, the wheel's
    /// direction, the buttons' sides.
    pub feel: Feel,
    /// Some device reported anything (a modifier alone too) since the
    /// program last took it: the screen wakes (ADR 0186).
    activity: bool,
    moved: bool,
    /// The key being held for repeat, and when it repeats next (ns).
    held: Option<(u16, i64)>,
    /// A logo key is down and nothing else has been pressed since.
    logo_alone: bool,
    last_scan: i64,
    /// How often to look for new devices (ns; a second by default).
    pub rescan_ns: i64,
    /// seatd's seat, for a program that is not root.
    seat: Option<crate::seat::Seat>,
    /// The session is in front (seatd enabled it; ADR 0185).
    seat_active: bool,
    /// The session went away (false) or came back (true) since asked.
    seat_change: Option<bool>,
    /// The kernel's uevent socket, when devices are opened as they come.
    uevents: Option<i32>,
    /// When the newest event of the last wait happened (monotonic ns;
    /// 0 if there was none).
    pub stamp: i64,
}

fn now_ns() -> i64 {
    let (s, ns) = slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC);
    s * 1_000_000_000 + ns
}

impl Drop for Inputs {
    fn drop(&mut self) {
        for d in &self.devices {
            let _ = io::close(d.fd);
        }
        if let Some(fd) = self.uevents {
            let _ = io::close(fd);
        }
    }
}

/// `p` if it is on one of `areas` (or there are none), else the nearest
/// point that is.
fn on_areas(areas: &[(f32, f32, f32, f32)], p: (f32, f32)) -> (f32, f32) {
    let inside = |a: &(f32, f32, f32, f32)| p.0 >= a.0 && p.1 >= a.1 && p.0 < a.0 + a.2 && p.1 < a.1 + a.3;
    if areas.is_empty() || areas.iter().any(inside) {
        return p;
    }
    let near = |a: &(f32, f32, f32, f32)| (p.0.clamp(a.0, a.0 + a.2 - 1.0), p.1.clamp(a.1, a.1 + a.3 - 1.0));
    let dist = |q: (f32, f32)| (q.0 - p.0) * (q.0 - p.0) + (q.1 - p.1) * (q.1 - p.1);
    areas.iter().map(near).min_by(|a, b| dist(*a).total_cmp(&dist(*b))).unwrap_or(p)
}

/// Key repeat: after half a second, 30 a second (common defaults).
const REPEAT_DELAY: i64 = 500_000_000;
const REPEAT_EVERY: i64 = 33_000_000;

impl Inputs {
    pub fn new(width: i32, height: i32) -> Inputs {
        Inputs::with_seat(width, height, None)
    }

    /// Inputs whose devices come from `seat` (when not root).
    pub fn with_seat(width: i32, height: i32, seat: Option<crate::seat::Seat>) -> Inputs {
        let (w, h) = (width as f32, height as f32);
        let mut i = Inputs {
            devices: Vec::new(),
            layout: Layout::US,
            mods: Mods::default(),
            dead: slate_term::keymap::Composer::new(),
            shifts: [false; 2],
            pointer: (w / 2.0, h / 2.0),
            screen: (w, h),
            areas: Vec::new(),
            displays_changed: false,
            pointer_seen: false,
            feel: Feel::default(),
            activity: false,
            moved: false,
            held: None,
            logo_alone: false,
            last_scan: 0,
            rescan_ns: 1_000_000_000,
            seat,
            seat_active: true,
            seat_change: None,
            uevents: None,
            stamp: 0,
        };
        i.scan();
        i
    }

    /// Open devices that have appeared (USB keyboards come late).
    fn scan(&mut self) {
        self.last_scan = now_ns();
        if !self.seat_active {
            return;
        }
        for e in fs::read_dir(b"/dev/input").unwrap_or_default() {
            if e.name.starts_with(b"event")
                && !self.devices.iter().any(|d| d.name == e.name)
                && let Some(d) = Device::open(&e.name, self.seat.as_mut())
            {
                self.devices.push(d);
            }
        }
    }

    /// Whether the session stepped aside (`Some(false)`: stop drawing) or
    /// came back to the front (`Some(true)`: light the displays again)
    /// since the last call (ADR 0185).
    pub fn take_seat_change(&mut self) -> Option<bool> {
        self.seat_change.take()
    }

    /// Whether the session is in front.
    pub fn seat_active(&self) -> bool {
        self.seat_active
    }

    /// Whether there is a seat to switch sessions on.
    pub fn has_seat(&self) -> bool {
        self.seat.is_some()
    }

    /// Ask seatd for the session on virtual console `vt` (Ctrl+Alt+Fn,
    /// "Switch person").
    pub fn switch_session(&mut self, vt: i32) {
        if let Some(s) = self.seat.as_mut() {
            s.switch_session(vt);
        }
    }

    /// What seatd said: step aside (the devices go; seatd revokes them
    /// anyway) or come back (they are opened again).
    fn seat_events(&mut self) {
        let Some(seat) = self.seat.as_mut() else { return };
        for e in seat.events() {
            match e {
                crate::seat::SeatEvent::Disable => {
                    for d in self.devices.drain(..) {
                        let _ = io::close(d.fd);
                    }
                    self.held = None;
                    self.mods = Mods::default();
                    self.shifts = [false; 2];
                    self.seat_active = false;
                    self.seat_change = Some(false);
                    if let Some(s) = self.seat.as_mut() {
                        s.disabled();
                    }
                }
                crate::seat::SeatEvent::Enable => {
                    self.seat_active = true;
                    self.seat_change = Some(true);
                    self.scan();
                }
            }
            if self.seat.is_none() {
                break;
            }
        }
    }

    /// Open input devices as soon as the kernel announces them on its
    /// uevent socket (netlink(7), group 1), not only when rescanning.
    pub fn watch_uevents(&mut self) {
        if self.uevents.is_none() {
            self.uevents = slate_rt::net::uevent_listen(1).ok();
        }
    }

    /// The modifier keys held now.
    pub fn mods(&self) -> Mods {
        self.mods
    }

    /// The devices' names, for the log.
    pub fn describe(&self) -> String {
        let names: Vec<String> = self.devices.iter().map(|d| String::from(lossy(&d.name))).collect();
        names.join(" ")
    }

    /// Wait up to `timeout_ms` for input; slate-ui events (the installer).
    pub fn wait(&mut self, timeout_ms: i32) -> Vec<Event> {
        self.wait_input(timeout_ms)
            .into_iter()
            .filter_map(|i| match i {
                Input::Key { key: Some(k), mods, .. } => Some(Event::Key(k, ui_mods(mods))),
                Input::Key { .. } | Input::Button { .. } | Input::Wheel { .. } => None,
                Input::Pointer(e) => Some(e),
            })
            .collect()
    }

    /// A key pressed (or repeated): what it types after a dead key before
    /// it (ADR 0117). A dead key is a press of its own that types
    /// nothing; the key after it types the accented letter, or the accent
    /// and then itself, the accent as a press with code 0 (no key of its
    /// own: the Linux bridge leaves it out, as the Linux program composes
    /// for itself).
    fn press(&mut self, code: u16, repeat: bool, out: &mut Vec<Input>) {
        use slate_term::keymap::Sym;
        let m = self.mods;
        let plain = !m.ctrl && !m.alt && !m.logo;
        let sym = slate_term::keymap::key(self.layout, code, m.shift, m.caps, m.altgr).filter(|_| plain);
        match sym {
            Some(Sym::Dead(_)) if repeat => {}
            Some(s @ Sym::Dead(_)) => {
                self.dead.feed(s);
                out.push(Input::Key { code, key: None, ch: None, mods: m });
            }
            Some(s @ Sym::Char(_)) if self.dead.pending() => {
                let typed: Vec<char> = self.dead.feed(s).chars().collect();
                for (i, &c) in typed.iter().enumerate() {
                    let code = if i + 1 == typed.len() { code } else { 0 };
                    out.push(Input::Key { code, key: Some(Key::Char(c)), ch: Some(c), mods: m });
                }
            }
            _ => {
                if sym.is_none() {
                    self.dead.reset();
                }
                let (key, ch) = (translate(self.layout, m, code), character(self.layout, m, code));
                out.push(Input::Key { code, key, ch, mods: m });
            }
        }
    }

    /// Wait up to `timeout_ms` for input and return what happened.
    pub fn wait_input(&mut self, timeout_ms: i32) -> Vec<Input> {
        self.wait_input_with(timeout_ms, &mut [])
    }

    /// The same, also waiting on `extra` descriptors: their `revents` say
    /// which are ready (a program's sockets).
    pub fn wait_input_with(&mut self, timeout_ms: i32, extra: &mut [io::PollFd]) -> Vec<Input> {
        let mut out = Vec::new();
        self.stamp = 0;
        let now = now_ns();
        if now - self.last_scan > self.rescan_ns {
            self.scan();
        }
        let mut timeout = timeout_ms;
        if let Some((_, at)) = self.held {
            timeout = timeout.min(((at - now).max(0) / 1_000_000) as i32);
        }
        let mut fds: Vec<io::PollFd> =
            self.devices.iter().map(|d| io::PollFd { fd: d.fd, events: io::POLLIN, revents: 0 }).collect();
        let devices = fds.len();
        fds.extend(extra.iter().map(|p| io::PollFd { revents: 0, ..*p }));
        let seat_at = fds.len();
        if let Some(s) = self.seat.as_ref() {
            fds.push(io::PollFd { fd: s.fd(), events: io::POLLIN, revents: 0 });
        }
        if let Some(fd) = self.uevents {
            fds.push(io::PollFd { fd, events: io::POLLIN, revents: 0 });
        }
        let _ = io::poll(&mut fds, timeout);
        for (e, p) in extra.iter_mut().zip(&fds[devices..]) {
            e.revents = p.revents;
        }
        if self.seat.is_some() && fds.get(seat_at).is_some_and(|p| p.revents != 0) {
            self.seat_events();
            // The devices changed under the descriptors polled.
            if self.seat_change.is_some() {
                return out;
            }
        }
        // A device added: open it now ("ACTION@DEVPATH", then KEY=value
        // fields; SUBSYSTEM=input for event devices).
        if let (Some(fd), Some(p)) = (self.uevents, fds.last())
            && p.fd == fd
            && p.revents != 0
        {
            let mut msg = [0u8; 4096];
            if let Ok(n) = io::read(fd, &mut msg) {
                let fields = || msg[..n].split(|&b| b == 0);
                if msg[..n].starts_with(b"add@") && fields().any(|f| f == b"SUBSYSTEM=input") {
                    self.scan();
                }
                // A display came, went or changed (the kernel's DRM
                // hotplug: SUBSYSTEM=drm, HOTPLUG=1).
                if fields().any(|f| f == b"SUBSYSTEM=drm") && fields().any(|f| f == b"HOTPLUG=1") {
                    self.displays_changed = true;
                }
            }
        }
        fds.truncate(devices);
        let mut gone = Vec::new();
        for (i, p) in fds.iter().enumerate() {
            if p.revents == 0 {
                continue;
            }
            let mut buf = [0u8; 24 * 64];
            loop {
                match io::read(self.devices[i].fd, &mut buf) {
                    Ok(n) if n >= 24 => {
                        for ev in buf[..n].as_chunks::<24>().0 {
                            // struct input_event: struct timeval (16
                            // bytes), type, code, value.
                            let ty = u16::from_le_bytes([ev[16], ev[17]]);
                            let code = u16::from_le_bytes([ev[18], ev[19]]);
                            let value = i32::from_le_bytes([ev[20], ev[21], ev[22], ev[23]]);
                            let sec = i64::from_le_bytes(ev[..8].try_into().unwrap());
                            let usec = i64::from_le_bytes(ev[8..16].try_into().unwrap());
                            self.stamp = self.stamp.max(sec * 1_000_000_000 + usec * 1000);
                            self.event(i, ty, code, value, &mut out);
                        }
                    }
                    Ok(_) => break,
                    Err(slate_rt::Errno::EAGAIN) => break,
                    Err(_) => {
                        gone.push(i);
                        break;
                    }
                }
            }
        }
        for i in gone.into_iter().rev() {
            let d = self.devices.remove(i);
            let _ = io::close(d.fd);
        }
        // Key repeat.
        if let Some((code, at)) = self.held {
            let now = now_ns();
            if now >= at {
                self.held = Some((code, now + REPEAT_EVERY));
                self.press(code, true, &mut out);
            }
        }
        out
    }

    /// Whether anything came from a device since the last call.
    pub fn take_activity(&mut self) -> bool {
        core::mem::take(&mut self.activity)
    }

    fn event(&mut self, dev: usize, ty: u16, code: u16, value: i32, out: &mut Vec<Input>) {
        if ty != EV_SYN {
            self.activity = true;
        }
        // A button or the wheel with the logo key down makes it no tap.
        if matches!((ty, code), (EV_KEY, BTN_LEFT | BTN_TOUCH | BTN_MIDDLE | BTN_RIGHT) | (EV_REL, REL_WHEEL)) {
            self.logo_alone = false;
        }
        match (ty, code) {
            // Left-handed: a mouse's right button is the first, its left
            // one opens menus (touches and tablets as they are).
            (EV_KEY, BTN_LEFT | BTN_RIGHT) if self.feel.left_handed => {
                let swapped = if code == BTN_LEFT { BTN_RIGHT } else { BTN_TOUCH };
                let mut f = self.feel;
                f.left_handed = false;
                let saved = core::mem::replace(&mut self.feel, f);
                self.event(dev, ty, swapped, value, out);
                self.feel = saved;
            }
            (EV_KEY, BTN_LEFT | BTN_TOUCH) => {
                let (x, y) = self.pointer;
                out.push(Input::Pointer(if value != 0 { Event::PointerDown(x, y) } else { Event::PointerUp(x, y) }));
            }
            (EV_KEY, BTN_MIDDLE | BTN_RIGHT) => {
                let (x, y) = self.pointer;
                let button = if code == BTN_MIDDLE { 2 } else { 3 };
                out.push(Input::Button { button, down: value != 0, x, y });
            }
            (EV_KEY, _) => self.key(code, value, out),
            // evdev's REL_WHEEL is positive away from the person.
            // Natural scrolling turns it round: the content follows the wheel.
            (EV_REL, REL_WHEEL) if value != 0 => {
                let (x, y) = self.pointer;
                let lines = if self.feel.natural { value } else { -value };
                out.push(Input::Wheel { lines, x, y });
            }
            (EV_REL, REL_X) => self.move_by(value as f32 * self.feel.factor(), 0.0),
            (EV_REL, REL_Y) => self.move_by(0.0, value as f32 * self.feel.factor()),
            (EV_ABS, ABS_X | ABS_Y) => {
                let Some(ranges) = self.devices[dev].abs else { return };
                let axis = usize::from(code == ABS_Y);
                let (lo, hi) = ranges[axis];
                let f = (value - lo) as f32 / (hi - lo).max(1) as f32;
                let size = if axis == 0 { self.screen.0 } else { self.screen.1 };
                let v = (f * (size - 1.0)).clamp(0.0, size - 1.0);
                if axis == 0 {
                    self.pointer.0 = v;
                } else {
                    self.pointer.1 = v;
                }
                self.pointer = on_areas(&self.areas, self.pointer);
                self.moved = true;
            }
            (EV_SYN, SYN_REPORT) if self.moved => {
                self.moved = false;
                self.pointer_seen = true;
                out.push(Input::Pointer(Event::PointerMove(self.pointer.0, self.pointer.1)));
            }
            _ => {}
        }
    }

    fn move_by(&mut self, dx: f32, dy: f32) {
        self.pointer.0 = (self.pointer.0 + dx).clamp(0.0, self.screen.0 - 1.0);
        self.pointer.1 = (self.pointer.1 + dy).clamp(0.0, self.screen.1 - 1.0);
        self.pointer = on_areas(&self.areas, self.pointer);
        self.moved = true;
    }

    /// The screen is now `w` × `h`, its displays `areas` (ADR 0170): the
    /// pointer stays where it was if that is still on one, else it goes
    /// to the nearest point that is.
    pub fn set_screen(&mut self, w: i32, h: i32, areas: Vec<(f32, f32, f32, f32)>) {
        self.screen = (w as f32, h as f32);
        self.areas = areas;
        self.pointer.0 = self.pointer.0.clamp(0.0, self.screen.0 - 1.0);
        self.pointer.1 = self.pointer.1.clamp(0.0, self.screen.1 - 1.0);
        self.pointer = on_areas(&self.areas, self.pointer);
    }

    fn key(&mut self, code: u16, value: i32, out: &mut Vec<Input>) {
        let down = value != 0;
        match code {
            KEY_LEFTSHIFT => self.shifts[0] = down,
            KEY_RIGHTSHIFT => self.shifts[1] = down,
            KEY_LEFTCTRL | KEY_RIGHTCTRL => self.mods.ctrl = down,
            KEY_RIGHTALT if self.layout.has_altgr() => self.mods.altgr = down,
            KEY_LEFTALT | KEY_RIGHTALT => self.mods.alt = down,
            KEY_LEFTMETA | KEY_RIGHTMETA => self.mods.logo = down,
            KEY_CAPSLOCK if value == 1 => self.mods.caps = !self.mods.caps,
            _ => {}
        }
        self.mods.shift = self.shifts[0] || self.shifts[1];
        match (code, value) {
            (KEY_LEFTMETA | KEY_RIGHTMETA, 1) => self.logo_alone = true,
            (KEY_LEFTMETA | KEY_RIGHTMETA, 0) => {
                if core::mem::take(&mut self.logo_alone) {
                    out.push(Input::Key { code, key: None, ch: None, mods: self.mods });
                }
            }
            // Any other key pressed while it is down (a shortcut).
            (_, 1) => self.logo_alone = false,
            _ => {}
        }
        if is_modifier(code) {
            return;
        }
        match value {
            1 => {
                self.held = Some((code, now_ns() + REPEAT_DELAY));
                self.press(code, false, out);
            }
            0 if self.held.is_some_and(|(c, _)| c == code) => self.held = None,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The logo key alone is a key of its own at its release; with
    /// another key, a button or the wheel between, it is only a modifier.
    #[test]
    fn logo_key_alone() {
        let mut i = Inputs::new(100, 100);
        let mut out = Vec::new();
        i.key(KEY_LEFTMETA, 1, &mut out);
        assert!(out.is_empty());
        i.key(KEY_LEFTMETA, 2, &mut out);
        i.key(KEY_LEFTMETA, 0, &mut out);
        assert!(matches!(out[..], [Input::Key { code: KEY_LEFTMETA, key: None, ch: None, mods }] if !mods.logo));
        // super + space: the space, then nothing at the release.
        out.clear();
        i.key(KEY_RIGHTMETA, 1, &mut out);
        i.key(KEY_SPACE, 1, &mut out);
        i.key(KEY_SPACE, 0, &mut out);
        i.key(KEY_RIGHTMETA, 0, &mut out);
        assert!(matches!(out[..], [Input::Key { code: KEY_SPACE, mods, .. }] if mods.logo));
        // A click while it is down.
        out.clear();
        i.key(KEY_LEFTMETA, 1, &mut out);
        i.event(0, EV_KEY, BTN_LEFT, 1, &mut out);
        i.event(0, EV_KEY, BTN_LEFT, 0, &mut out);
        i.key(KEY_LEFTMETA, 0, &mut out);
        assert!(!out.iter().any(|e| matches!(e, Input::Key { .. })));
    }

    #[test]
    fn the_pointer_as_liked() {
        let mut i = Inputs::new(1000, 800);
        let mut out = Vec::new();
        i.pointer = (100.0, 100.0);
        i.feel.speed = 2;
        i.event(0, EV_REL, REL_X, 10, &mut out);
        assert_eq!(i.pointer.0, 120.0);
        i.feel.speed = -2;
        i.event(0, EV_REL, REL_Y, 10, &mut out);
        assert_eq!(i.pointer.1, 105.0);
        // The wheel turned round.
        i.event(0, EV_REL, REL_WHEEL, 1, &mut out);
        i.feel.natural = true;
        i.event(0, EV_REL, REL_WHEEL, 1, &mut out);
        let lines: Vec<i32> =
            out.iter().filter_map(|e| if let Input::Wheel { lines, .. } = e { Some(*lines) } else { None }).collect();
        assert_eq!(lines, [-1, 1]);
        // Left-handed: the right button clicks, the left opens menus.
        out.clear();
        i.feel.left_handed = true;
        i.event(0, EV_KEY, BTN_RIGHT, 1, &mut out);
        i.event(0, EV_KEY, BTN_LEFT, 1, &mut out);
        assert!(matches!(out[0], Input::Pointer(Event::PointerDown(..))));
        assert!(matches!(out[1], Input::Button { button: 3, down: true, .. }));
    }

    /// German's dead acute: a press that types nothing, then é; then ´
    /// and q, the accent as a press of no key (ADR 0117).
    #[test]
    fn dead_keys() {
        let mut i = Inputs::new(100, 100);
        i.layout = Layout::named("de");
        let mut out = Vec::new();
        for code in [13, 18, 13, 16] {
            i.key(code, 1, &mut out);
            i.key(code, 0, &mut out);
        }
        let typed: Vec<(u16, Option<char>)> = out
            .iter()
            .filter_map(|e| match e {
                Input::Key { code, ch, .. } => Some((*code, *ch)),
                _ => None,
            })
            .collect();
        assert_eq!(typed, [(13, None), (18, Some('é')), (13, None), (0, Some('´')), (16, Some('q'))]);
    }

    #[test]
    fn layouts() {
        let plain = Mods::default();
        let shift = Mods { shift: true, ..Mods::default() };
        let caps = Mods { caps: true, ..Mods::default() };
        assert_eq!(translate(Layout::US, plain, 16), Some(Key::Char('q')));
        assert_eq!(translate(Layout::US, shift, 16), Some(Key::Char('Q')));
        assert_eq!(translate(Layout::US, caps, 16), Some(Key::Char('Q')));
        assert_eq!(translate(Layout::US, caps, 2), Some(Key::Char('1')));
        assert_eq!(translate(Layout::US, shift, 3), Some(Key::Char('@')));
        assert_eq!(translate(Layout::named("gb"), shift, 3), Some(Key::Char('"')));
        assert_eq!(translate(Layout::named("gb"), shift, 4), Some(Key::Char('£')));
        assert_eq!(translate(Layout::named("gb"), shift, 40), Some(Key::Char('@')));
        assert_eq!(translate(Layout::US, shift, 40), Some(Key::Char('"')));
        assert_eq!(translate(Layout::US, plain, 53), Some(Key::Char('/')));
        assert_eq!(translate(Layout::US, shift, KEY_TAB), Some(Key::BackTab));
        // ctrl + a is a shortcut's letter (the modifiers travel with it);
        // alt leaves keys alone; Home, End and Delete are keys of their own.
        assert_eq!(translate(Layout::US, Mods { ctrl: true, ..plain }, 30), Some(Key::Char('a')));
        assert_eq!(translate(Layout::US, Mods { alt: true, ..plain }, 30), None);
        assert_eq!(translate(Layout::US, plain, KEY_HOME), Some(Key::Home));
        assert_eq!(translate(Layout::US, plain, KEY_DELETE), Some(Key::Delete));
        assert_eq!(translate(Layout::US, plain, 0x200), None);
    }

    #[test]
    fn the_pointer_stays_on_a_display() {
        // 1280x800 beside a 1024x768 one: the strip under the second is
        // on neither.
        let areas = [(0.0, 0.0, 1280.0, 800.0), (1280.0, 0.0, 1024.0, 768.0)];
        assert_eq!(on_areas(&areas, (1500.0, 790.0)), (1500.0, 767.0));
        assert_eq!(on_areas(&areas, (100.0, 790.0)), (100.0, 790.0));
        assert_eq!(on_areas(&[], (5000.0, 5000.0)), (5000.0, 5000.0));
    }
}
