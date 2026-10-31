// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strata's client protocol (ADR 0037), on a Unix stream socket: an app
//! creates windows, gives each two buffers of shared memory (file
//! descriptors passed with `Buffer` messages) and says which one to show
//! and what changed (`Damage`); Strata tells it when it stops reading a
//! buffer (`Release`), so the app never draws into the one being shown
//! (ADR 0039);
//! Strata tells it each window's size and focus, and passes keys, pointer
//! events and close requests. Strata also keeps the clipboard (ADR 0038):
//! an app offers text with `Copy`, and asks for it with `Paste`; only the
//! app with the focused window may do either.
//!
//! Files go between the desktop and apps by dragging (ADR 0156): an app
//! dragging files out of a window says which (`Drag`), and Strata, which
//! sees where the button comes up, moves them onto the desktop or tells
//! the window they were dropped on (`Drop`); so does a drag of the
//! desktop's own icons. Paths are one per line. A drop with ctrl held
//! copies rather than moves (`copy`, since version 7).
//!
//! Strata says when it has put a window's new contents on the screen
//! (`Frame`, since version 8), so an app that draws continuously draws at
//! the screen's pace and not faster. A buffer may be `OPAQUE` (since
//! version 8): its fourth byte means nothing (a Linux compositor's
//! XRGB8888 frames, M31), and Strata shows it without blending.
//!
//! Every message is a record: a 4-byte little-endian length of the rest,
//! a 2-byte type, then the fields (little-endian integers; strings as a
//! 2-byte length and UTF-8, clipboard text as a 4-byte length and UTF-8). Buffers hold 32-bit 0xAARRGGBB pixels, rows
//! `width` apart.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::string::String;
use alloc::vec::Vec;

/// The protocol's version, in `Hello`.
pub const VERSION: u32 = 10;
/// The largest record accepted.
pub const MAX_RECORD: usize = 64 * 1024;
/// The most clipboard text a record carries (longer text is cut, at a
/// character's boundary).
pub const MAX_TEXT: usize = MAX_RECORD - 64;

/// `Buffer`'s flags.
pub mod buffer {
    /// The pixels' fourth byte means nothing: the buffer is opaque.
    pub const OPAQUE: u8 = 1;
}

/// Which clipboard `Copy` and `Paste` mean: the one ctrl + shift + c/v use,
/// or the selection (pasted with the middle button).
pub mod clipboard {
    pub const CLIPBOARD: u8 = 0;
    pub const SELECTION: u8 = 1;
}

/// From an app to Strata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Hello {
        version: u32,
    },
    /// A new window, numbered by the app; `path` may be empty.
    Create {
        win: u32,
        app: String,
        path: String,
    },
    /// A new title, and the process it describes (0: the app itself):
    /// a terminal names its foreground program, whose domain Strata then
    /// shows if it is the app's descendant.
    Title {
        win: u32,
        app: String,
        path: String,
        pid: u32,
    },
    /// Buffer `index` (0 or 1) of the window's pixels: comes with one file
    /// descriptor to map, at least `width * height * 4` bytes; `flags`
    /// are `buffer::*`.
    Buffer {
        win: u32,
        width: u32,
        height: u32,
        index: u8,
        flags: u8,
    },
    /// Show buffer `index` now; this part of it changed. The buffer shown
    /// before is released (`Release`).
    Damage {
        win: u32,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        index: u8,
    },
    Destroy {
        win: u32,
    },
    /// Text for a clipboard (`clipboard::*`).
    Copy {
        which: u8,
        text: String,
    },
    /// The clipboard's text, please: Strata answers with `Paste`.
    Paste {
        win: u32,
        which: u8,
    },
    /// The sizes the window's app asks for, in logical pixels (0: none):
    /// the smallest it takes, and the size it would like (ADR 0102).
    Hints {
        win: u32,
        min_width: u32,
        min_height: u32,
        width: u32,
        height: u32,
    },
    /// Keep the screen from locking by itself while the window shows
    /// something to watch (a video playing), or stop (ADR 0102's second
    /// addendum). The window going ends it too.
    Inhibit {
        win: u32,
        on: bool,
    },
    /// Resize the window in steps (a terminal's cells; ADR 0102's third
    /// addendum): its content a base size and a whole number of steps,
    /// in hundredths of a logical pixel (0 steps: none).
    Steps {
        win: u32,
        base_width: u32,
        base_height: u32,
        width: u32,
        height: u32,
    },
    /// The app is dragging these files out of the window, with the left
    /// button held (ADR 0156): where the button comes up, outside the
    /// window, decides what becomes of them. One path per line.
    Drag {
        win: u32,
        paths: String,
    },
    /// The pointer's shape over the window's content from now on
    /// (`cursor::*`; since version 9, ADR 0186).
    Cursor {
        win: u32,
        shape: u8,
    },
    /// A notification (since version 10, ADR 0186): from `app`, a summary
    /// and a body, at an urgency (`urgency::*`). `key` is the app's own
    /// number for it: another with the same key (not 0) replaces it.
    Notify {
        key: u32,
        app: String,
        summary: String,
        body: String,
        urgency: u8,
    },
    /// The app's notification `key` is no longer wanted.
    Unnotify {
        key: u32,
    },
}

/// How urgent a notification is (`Notify`), as the Desktop
/// Notifications Specification's urgency hint has it.
pub mod urgency {
    pub const LOW: u8 = 0;
    pub const NORMAL: u8 = 1;
    /// Shown until dismissed, even with Do Not Disturb on.
    pub const CRITICAL: u8 = 2;
}

/// Pointer shapes an app may ask for (`Cursor`).
pub mod cursor {
    pub const ARROW: u8 = 0;
    /// A link or a button.
    pub const HAND: u8 = 1;
    /// Text that can be selected or typed in.
    pub const TEXT: u8 = 2;
    /// The app is busy.
    pub const BUSY: u8 = 3;
    /// Something being moved.
    pub const MOVE: u8 = 4;
    /// What is under the pointer won't take it.
    pub const NOT_ALLOWED: u8 = 5;
}

/// Modifier bits in `Key`.
pub mod mods {
    pub const SHIFT: u8 = 1;
    pub const CTRL: u8 = 2;
    pub const ALT: u8 = 4;
    pub const LOGO: u8 = 8;
    /// AltGr (the right Alt key, in layouts that have it; ADR 0117).
    pub const ALTGR: u8 = 16;
}

/// What a `Pointer` event is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointerKind {
    Move,
    Down,
    Up,
}

/// From Strata to an app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The window's size in device pixels, the scale (in hundredths) and
    /// whether it has the keyboard.
    Configure { win: u32, width: u32, height: u32, scale: u32, focused: bool },
    /// A key press: the evdev code, the character it types under the
    /// layout whatever the modifiers (0 for none), and the modifiers.
    Key { win: u32, code: u16, ch: u32, mods: u8 },
    /// A pointer event in the window's device pixels: `button` is 1 (left),
    /// 2 (middle) or 3 (right) for Down and Up, 0 for Move. Moves come
    /// while the pointer is over the window and, while a button is held,
    /// even outside it. `mods` are the modifiers held (as in `Key`).
    Pointer { win: u32, kind: PointerKind, button: u8, x: i32, y: i32, mods: u8 },
    /// The wheel turned over the window: `lines` < 0 is up (back).
    Scroll { win: u32, x: i32, y: i32, lines: i32, mods: u8 },
    /// The person closed the window.
    Close { win: u32 },
    /// The answer to `Paste`.
    Paste { win: u32, which: u8, text: String },
    /// Strata no longer reads buffer `index`: the app may draw into it.
    Release { win: u32, index: u8 },
    /// Files dragged from the desktop or another app were dropped on the
    /// window at (x, y), device pixels (ADR 0156). One path per line;
    /// `copy`: ctrl was held, so they are copied, not moved.
    Drop { win: u32, x: i32, y: i32, paths: String, copy: bool },
    /// The window's contents shown last are on the screen (or the window
    /// isn't, and won't be drawn): time to draw the next frame.
    Frame { win: u32 },
}

const HELLO: u16 = 1;
const CREATE: u16 = 2;
const TITLE: u16 = 3;
const BUFFER: u16 = 4;
const DAMAGE: u16 = 5;
const DESTROY: u16 = 6;
const COPY: u16 = 7;
const PASTE: u16 = 8;
const HINTS: u16 = 9;
const INHIBIT: u16 = 10;
const STEPS: u16 = 11;
const DRAG: u16 = 12;
const CURSOR: u16 = 13;
const NOTIFY: u16 = 14;
const UNNOTIFY: u16 = 15;
const CONFIGURE: u16 = 101;
const KEY: u16 = 102;
const POINTER: u16 = 103;
const CLOSE: u16 = 104;
const SCROLL: u16 = 105;
const PASTED: u16 = 106;
const RELEASE: u16 = 107;
const DROP: u16 = 108;
const FRAME: u16 = 109;

/// `s` cut to at most `max` bytes, at a character's boundary.
pub fn cut(s: &str, max: usize) -> &str {
    let mut n = s.len().min(max);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    &s[..n]
}

/// A record being written.
struct Out(Vec<u8>);

impl Out {
    fn new(ty: u16) -> Out {
        let mut v = alloc::vec![0; 4];
        v.extend_from_slice(&ty.to_le_bytes());
        Out(v)
    }
    fn u8(mut self, x: u8) -> Out {
        self.0.push(x);
        self
    }
    fn u16(mut self, x: u16) -> Out {
        self.0.extend_from_slice(&x.to_le_bytes());
        self
    }
    fn u32(mut self, x: u32) -> Out {
        self.0.extend_from_slice(&x.to_le_bytes());
        self
    }
    fn str(mut self, s: &str) -> Out {
        let b = &s.as_bytes()[..s.len().min(4096)];
        self.0.extend_from_slice(&(b.len() as u16).to_le_bytes());
        self.0.extend_from_slice(b);
        self
    }
    fn text(mut self, s: &str) -> Out {
        let b = cut(s, MAX_TEXT).as_bytes();
        self.0.extend_from_slice(&(b.len() as u32).to_le_bytes());
        self.0.extend_from_slice(b);
        self
    }
    fn done(mut self) -> Vec<u8> {
        let n = (self.0.len() - 4) as u32;
        self.0[..4].copy_from_slice(&n.to_le_bytes());
        self.0
    }
}

/// A record being read.
struct In<'a>(&'a [u8]);

impl In<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn str(&mut self) -> Option<String> {
        let n = self.u16()? as usize;
        core::str::from_utf8(self.take(n)?).ok().map(String::from)
    }
    fn text(&mut self) -> Option<String> {
        let n = self.u32()? as usize;
        core::str::from_utf8(self.take(n)?).ok().map(String::from)
    }
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Request::Hello { version } => Out::new(HELLO).u32(*version),
            Request::Create { win, app, path } => Out::new(CREATE).u32(*win).str(app).str(path),
            Request::Title { win, app, path, pid } => Out::new(TITLE).u32(*win).str(app).str(path).u32(*pid),
            Request::Buffer { win, width, height, index, flags } => {
                Out::new(BUFFER).u32(*win).u32(*width).u32(*height).u8(*index).u8(*flags)
            }
            Request::Damage { win, x, y, width, height, index } => {
                Out::new(DAMAGE).u32(*win).u32(*x).u32(*y).u32(*width).u32(*height).u8(*index)
            }
            Request::Destroy { win } => Out::new(DESTROY).u32(*win),
            Request::Copy { which, text } => Out::new(COPY).u8(*which).text(text),
            Request::Paste { win, which } => Out::new(PASTE).u32(*win).u8(*which),
            Request::Hints { win, min_width, min_height, width, height } => {
                Out::new(HINTS).u32(*win).u32(*min_width).u32(*min_height).u32(*width).u32(*height)
            }
            Request::Inhibit { win, on } => Out::new(INHIBIT).u32(*win).u8(u8::from(*on)),
            Request::Cursor { win, shape } => Out::new(CURSOR).u32(*win).u8(*shape),
            Request::Notify { key, app, summary, body, urgency } => {
                Out::new(NOTIFY).u32(*key).str(app).str(summary).str(body).u8(*urgency)
            }
            Request::Unnotify { key } => Out::new(UNNOTIFY).u32(*key),
            Request::Steps { win, base_width, base_height, width, height } => {
                Out::new(STEPS).u32(*win).u32(*base_width).u32(*base_height).u32(*width).u32(*height)
            }
            Request::Drag { win, paths } => Out::new(DRAG).u32(*win).text(paths),
        }
        .done()
    }

    fn decode(ty: u16, r: &mut In<'_>) -> Option<Request> {
        Some(match ty {
            HELLO => Request::Hello { version: r.u32()? },
            CREATE => Request::Create { win: r.u32()?, app: r.str()?, path: r.str()? },
            TITLE => Request::Title { win: r.u32()?, app: r.str()?, path: r.str()?, pid: r.u32()? },
            BUFFER => {
                Request::Buffer { win: r.u32()?, width: r.u32()?, height: r.u32()?, index: r.u8()?, flags: r.u8()? }
            }
            DAMAGE => Request::Damage {
                win: r.u32()?,
                x: r.u32()?,
                y: r.u32()?,
                width: r.u32()?,
                height: r.u32()?,
                index: r.u8()?,
            },
            DESTROY => Request::Destroy { win: r.u32()? },
            COPY => Request::Copy { which: r.u8()?, text: r.text()? },
            PASTE => Request::Paste { win: r.u32()?, which: r.u8()? },
            HINTS => Request::Hints {
                win: r.u32()?,
                min_width: r.u32()?,
                min_height: r.u32()?,
                width: r.u32()?,
                height: r.u32()?,
            },
            INHIBIT => Request::Inhibit { win: r.u32()?, on: r.u8()? != 0 },
            CURSOR => Request::Cursor { win: r.u32()?, shape: r.u8()? },
            NOTIFY => {
                Request::Notify { key: r.u32()?, app: r.str()?, summary: r.str()?, body: r.str()?, urgency: r.u8()? }
            }
            UNNOTIFY => Request::Unnotify { key: r.u32()? },
            STEPS => Request::Steps {
                win: r.u32()?,
                base_width: r.u32()?,
                base_height: r.u32()?,
                width: r.u32()?,
                height: r.u32()?,
            },
            DRAG => Request::Drag { win: r.u32()?, paths: r.text()? },
            _ => return None,
        })
    }
}

impl Event {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Event::Configure { win, width, height, scale, focused } => {
                Out::new(CONFIGURE).u32(*win).u32(*width).u32(*height).u32(*scale).u8(u8::from(*focused))
            }
            Event::Key { win, code, ch, mods } => Out::new(KEY).u32(*win).u16(*code).u32(*ch).u8(*mods),
            Event::Pointer { win, kind, button, x, y, mods } => {
                let k = match kind {
                    PointerKind::Move => 0,
                    PointerKind::Down => 1,
                    PointerKind::Up => 2,
                };
                Out::new(POINTER).u32(*win).u8(k).u8(*button).u32(*x as u32).u32(*y as u32).u8(*mods)
            }
            Event::Scroll { win, x, y, lines, mods } => {
                Out::new(SCROLL).u32(*win).u32(*x as u32).u32(*y as u32).u32(*lines as u32).u8(*mods)
            }
            Event::Close { win } => Out::new(CLOSE).u32(*win),
            Event::Paste { win, which, text } => Out::new(PASTED).u32(*win).u8(*which).text(text),
            Event::Release { win, index } => Out::new(RELEASE).u32(*win).u8(*index),
            Event::Drop { win, x, y, paths, copy } => {
                Out::new(DROP).u32(*win).u32(*x as u32).u32(*y as u32).text(paths).u8(u8::from(*copy))
            }
            Event::Frame { win } => Out::new(FRAME).u32(*win),
        }
        .done()
    }

    fn decode(ty: u16, r: &mut In<'_>) -> Option<Event> {
        Some(match ty {
            CONFIGURE => Event::Configure {
                win: r.u32()?,
                width: r.u32()?,
                height: r.u32()?,
                scale: r.u32()?,
                focused: r.u8()? != 0,
            },
            KEY => Event::Key { win: r.u32()?, code: r.u16()?, ch: r.u32()?, mods: r.u8()? },
            POINTER => {
                let win = r.u32()?;
                let kind = match r.u8()? {
                    0 => PointerKind::Move,
                    1 => PointerKind::Down,
                    _ => PointerKind::Up,
                };
                Event::Pointer { win, kind, button: r.u8()?, x: r.u32()? as i32, y: r.u32()? as i32, mods: r.u8()? }
            }
            SCROLL => Event::Scroll {
                win: r.u32()?,
                x: r.u32()? as i32,
                y: r.u32()? as i32,
                lines: r.u32()? as i32,
                mods: r.u8()?,
            },
            CLOSE => Event::Close { win: r.u32()? },
            PASTED => Event::Paste { win: r.u32()?, which: r.u8()?, text: r.text()? },
            RELEASE => Event::Release { win: r.u32()?, index: r.u8()? },
            DROP => Event::Drop {
                win: r.u32()?,
                x: r.u32()? as i32,
                y: r.u32()? as i32,
                paths: r.text()?,
                copy: r.u8()? != 0,
            },
            FRAME => Event::Frame { win: r.u32()? },
            _ => return None,
        })
    }
}

/// What reading a stream gave: a message, nothing complete yet, or a
/// broken stream (a record too large or that does not parse).
#[derive(Debug, PartialEq, Eq)]
pub enum Next<T> {
    Message(T),
    Incomplete,
    Broken,
}

/// The next record in `buf`, removing it.
fn next_record(buf: &mut Vec<u8>) -> Next<(u16, Vec<u8>)> {
    if buf.len() < 4 {
        return Next::Incomplete;
    }
    let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if !(2..=MAX_RECORD).contains(&n) {
        return Next::Broken;
    }
    if buf.len() < 4 + n {
        return Next::Incomplete;
    }
    let rec: Vec<u8> = buf.drain(..4 + n).skip(4).collect();
    let ty = u16::from_le_bytes([rec[0], rec[1]]);
    Next::Message((ty, rec[2..].to_vec()))
}

/// The next request in a stream buffer.
pub fn next_request(buf: &mut Vec<u8>) -> Next<Request> {
    match next_record(buf) {
        Next::Message((ty, body)) => match Request::decode(ty, &mut In(&body)) {
            Some(r) => Next::Message(r),
            None => Next::Broken,
        },
        Next::Incomplete => Next::Incomplete,
        Next::Broken => Next::Broken,
    }
}

/// The next event in a stream buffer.
pub fn next_event(buf: &mut Vec<u8>) -> Next<Event> {
    match next_record(buf) {
        Next::Message((ty, body)) => match Event::decode(ty, &mut In(&body)) {
            Some(e) => Next::Message(e),
            None => Next::Broken,
        },
        Next::Incomplete => Next::Incomplete,
        Next::Broken => Next::Broken,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn round_trips() {
        let reqs = [
            Request::Hello { version: VERSION },
            Request::Create { win: 1, app: "terminal".to_string(), path: "~/slate".to_string() },
            Request::Title { win: 1, app: "etch".to_string(), path: String::new(), pid: 42 },
            Request::Buffer { win: 1, width: 800, height: 600, index: 1, flags: 0 },
            Request::Buffer { win: 2, width: 64, height: 32, index: 0, flags: buffer::OPAQUE },
            Request::Damage { win: 1, x: 0, y: 2, width: 800, height: 20, index: 1 },
            Request::Destroy { win: 1 },
            Request::Copy { which: clipboard::SELECTION, text: "ls -l\nécho".to_string() },
            Request::Paste { win: 1, which: clipboard::CLIPBOARD },
            Request::Hints { win: 1, min_width: 400, min_height: 300, width: 600, height: 0 },
            Request::Inhibit { win: 1, on: true },
            Request::Steps { win: 1, base_width: 3200, base_height: 2400, width: 780, height: 2100 },
            Request::Drag { win: 1, paths: "/root/a.txt\n/root/b c".to_string() },
            Request::Cursor { win: 1, shape: cursor::TEXT },
            Request::Notify {
                key: 3,
                app: "Clock".to_string(),
                summary: "Alarm".to_string(),
                body: "07:30 Wake up".to_string(),
                urgency: urgency::CRITICAL,
            },
            Request::Unnotify { key: 3 },
        ];
        let mut stream: Vec<u8> = reqs.iter().flat_map(|r| r.encode()).collect();
        // Fed in two halves: the first gives what is complete.
        let mut half: Vec<u8> = stream.drain(..stream.len() / 2).collect();
        let mut got = Vec::new();
        while let Next::Message(r) = next_request(&mut half) {
            got.push(r);
        }
        half.extend(stream);
        while let Next::Message(r) = next_request(&mut half) {
            got.push(r);
        }
        assert_eq!(got, reqs);
        assert!(half.is_empty());

        let evs = [
            Event::Configure { win: 3, width: 846, height: 817, scale: 100, focused: true },
            Event::Key { win: 3, code: 30, ch: 'a' as u32, mods: mods::CTRL },
            Event::Pointer { win: 3, kind: PointerKind::Down, button: 2, x: -1, y: 40, mods: mods::SHIFT },
            Event::Scroll { win: 3, x: 5, y: 6, lines: -3, mods: 0 },
            Event::Close { win: 3 },
            Event::Paste { win: 3, which: clipboard::CLIPBOARD, text: "pasted".to_string() },
            Event::Release { win: 3, index: 0 },
            Event::Drop { win: 3, x: 120, y: -4, paths: "/root/Desktop/notes.txt".to_string(), copy: false },
            Event::Drop { win: 3, x: 0, y: 0, paths: "/root/a".to_string(), copy: true },
            Event::Frame { win: 3 },
        ];
        let mut stream: Vec<u8> = evs.iter().flat_map(|e| e.encode()).collect();
        let mut got = Vec::new();
        while let Next::Message(e) = next_event(&mut stream) {
            got.push(e);
        }
        assert_eq!(got, evs);
    }

    #[test]
    fn bad_streams() {
        let mut huge = (MAX_RECORD as u32 + 1).to_le_bytes().to_vec();
        assert_eq!(next_request(&mut huge), Next::Broken);
        let mut unknown = Out::new(99).u32(1).done();
        assert_eq!(next_request(&mut unknown), Next::Broken);
        // Too short for its type.
        let mut short = Out::new(BUFFER).u32(1).done();
        assert_eq!(next_request(&mut short), Next::Broken);
        // Clipboard text is cut to fit a record, between characters.
        let long = "é".repeat(MAX_TEXT);
        let mut rec = Request::Copy { which: 0, text: long }.encode();
        assert!(rec.len() <= MAX_RECORD + 4);
        match next_request(&mut rec) {
            Next::Message(Request::Copy { text, .. }) => assert_eq!(text.len(), MAX_TEXT / 2 * 2),
            other => panic!("{other:?}"),
        }
        let mut partial = Request::Destroy { win: 1 }.encode();
        partial.pop();
        assert_eq!(next_request(&mut partial), Next::Incomplete);
    }
}
