// SPDX-License-Identifier: MIT OR Apache-2.0

//! stty: show or change a terminal's settings (POSIX stty, with GNU's
//! names, `-a`, `-g`, `size`, `speed` and the combination settings). The
//! listing follows GNU's layout. Flag values and control-character
//! indexes from musl `bits/termios.h` (ADR 0009).

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, io, lossy, print, println, term};

use crate::util::{error, parse_num};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    C,
    I,
    O,
    L,
}

/// A flag: its name, word, mask and value. `choice` marks one value of
/// a multi-bit field (cs8, tab3...), shown only when it is the one set.
struct Flag {
    name: &'static str,
    field: Field,
    mask: u32,
    bits: u32,
    choice: bool,
}

const fn f(name: &'static str, field: Field, bits: u32) -> Flag {
    Flag { name, field, mask: bits, bits, choice: false }
}

const fn m(name: &'static str, field: Field, mask: u32, bits: u32) -> Flag {
    Flag { name, field, mask, bits, choice: true }
}

// In the order stty -a lists them.
const FLAGS: &[Flag] = &[
    f("parenb", Field::C, 0o400),
    f("parodd", Field::C, 0o1000),
    f("cmspar", Field::C, 0o10000000000),
    m("cs5", Field::C, 0o60, 0),
    m("cs6", Field::C, 0o60, 0o20),
    m("cs7", Field::C, 0o60, 0o40),
    m("cs8", Field::C, 0o60, 0o60),
    f("hupcl", Field::C, 0o2000),
    f("cstopb", Field::C, 0o100),
    f("cread", Field::C, 0o200),
    f("clocal", Field::C, 0o4000),
    f("crtscts", Field::C, 0o20000000000),
    f("ignbrk", Field::I, 1),
    f("brkint", Field::I, 2),
    f("ignpar", Field::I, 4),
    f("parmrk", Field::I, 0o10),
    f("inpck", Field::I, 0o20),
    f("istrip", Field::I, 0o40),
    f("inlcr", Field::I, 0o100),
    f("igncr", Field::I, 0o200),
    f("icrnl", Field::I, 0o400),
    f("ixon", Field::I, 0o2000),
    f("ixoff", Field::I, 0o10000),
    f("iuclc", Field::I, 0o1000),
    f("ixany", Field::I, 0o4000),
    f("imaxbel", Field::I, 0o20000),
    f("iutf8", Field::I, 0o40000),
    f("opost", Field::O, 1),
    f("olcuc", Field::O, 2),
    f("ocrnl", Field::O, 0o10),
    f("onlcr", Field::O, 4),
    f("onocr", Field::O, 0o20),
    f("onlret", Field::O, 0o40),
    f("ofill", Field::O, 0o100),
    f("ofdel", Field::O, 0o200),
    m("nl0", Field::O, 0o400, 0),
    m("nl1", Field::O, 0o400, 0o400),
    m("cr0", Field::O, 0o3000, 0),
    m("cr1", Field::O, 0o3000, 0o1000),
    m("cr2", Field::O, 0o3000, 0o2000),
    m("cr3", Field::O, 0o3000, 0o3000),
    m("tab0", Field::O, 0o14000, 0),
    m("tab1", Field::O, 0o14000, 0o4000),
    m("tab2", Field::O, 0o14000, 0o10000),
    m("tab3", Field::O, 0o14000, 0o14000),
    m("bs0", Field::O, 0o20000, 0),
    m("bs1", Field::O, 0o20000, 0o20000),
    m("vt0", Field::O, 0o40000, 0),
    m("vt1", Field::O, 0o40000, 0o40000),
    m("ff0", Field::O, 0o100000, 0),
    m("ff1", Field::O, 0o100000, 0o100000),
    f("isig", Field::L, 1),
    f("icanon", Field::L, 2),
    f("iexten", Field::L, 0o100000),
    f("echo", Field::L, 0o10),
    f("echoe", Field::L, 0o20),
    f("echok", Field::L, 0o40),
    f("echonl", Field::L, 0o100),
    f("noflsh", Field::L, 0o200),
    f("xcase", Field::L, 4),
    f("tostop", Field::L, 0o400),
    f("echoprt", Field::L, 0o2000),
    f("echoctl", Field::L, 0o1000),
    f("echoke", Field::L, 0o4000),
    f("flusho", Field::L, 0o10000),
    f("extproc", Field::L, 0o200000),
];

/// Control characters: name and c_cc index, in stty -a's order.
const CHARS: &[(&str, usize)] = &[
    ("intr", 0),
    ("quit", 1),
    ("erase", 2),
    ("kill", 3),
    ("eof", 4),
    ("eol", 11),
    ("eol2", 16),
    ("swtch", 7),
    ("start", 8),
    ("stop", 9),
    ("susp", 10),
    ("rprnt", 12),
    ("werase", 14),
    ("lnext", 15),
    ("discard", 13),
];
const VTIME: usize = 5;
const VMIN: usize = 6;

/// The values `sane` gives the control characters (indexes as above).
const SANE_CC: &[(usize, u8)] = &[
    (0, 3),
    (1, 0x1c),
    (2, 0x7f),
    (3, 0x15),
    (4, 4),
    (8, 0x11),
    (9, 0x13),
    (10, 0x1a),
    (12, 0x12),
    (13, 0x0f),
    (14, 0x17),
    (15, 0x16),
    (11, 0),
    (16, 0),
    (7, 0),
];

/// c_cflag's speed bits, and each speed's value in them (speed, bits).
pub const CBAUD: u32 = 0o10017;
/// The input speed's bits are CBAUD's this far up (CIBAUD, musl
/// `bits/termios.h`); 0 means "the output speed".
const IBSHIFT: u32 = 16;
pub const SPEEDS: &[(u32, u32)] = &[
    (0, 0),
    (50, 1),
    (75, 2),
    (110, 3),
    (134, 4),
    (150, 5),
    (200, 6),
    (300, 7),
    (600, 8),
    (1200, 9),
    (1800, 10),
    (2400, 11),
    (4800, 12),
    (9600, 13),
    (19200, 14),
    (38400, 15),
    (57600, 0o10001),
    (115200, 0o10002),
    (230400, 0o10003),
    (460800, 0o10004),
    (500000, 0o10005),
    (576000, 0o10006),
    (921600, 0o10007),
    (1000000, 0o10010),
    (1152000, 0o10011),
    (1500000, 0o10012),
    (2000000, 0o10013),
    (2500000, 0o10014),
    (3000000, 0o10015),
    (3500000, 0o10016),
    (4000000, 0o10017),
];

fn word(t: &mut term::Termios, fl: Field) -> &mut u32 {
    match fl {
        Field::C => &mut t.cflag,
        Field::I => &mut t.iflag,
        Field::O => &mut t.oflag,
        Field::L => &mut t.lflag,
    }
}

fn is_set(t: &term::Termios, fl: &Flag) -> bool {
    let w = match fl.field {
        Field::C => t.cflag,
        Field::I => t.iflag,
        Field::O => t.oflag,
        Field::L => t.lflag,
    };
    w & fl.mask == fl.bits
}

fn set(t: &mut term::Termios, name: &str, on: bool) -> bool {
    let Some(fl) = FLAGS.iter().find(|x| x.name == name) else { return false };
    let w = word(t, fl.field);
    if fl.choice {
        // A value of a multi-bit field: `-` makes no sense.
        if !on {
            return false;
        }
        *w = (*w & !fl.mask) | fl.bits;
    } else if on {
        *w |= fl.bits;
    } else {
        *w &= !fl.bits;
    }
    true
}

fn sane(t: &mut term::Termios) {
    for n in [
        "cread", "brkint", "icrnl", "imaxbel", "opost", "onlcr", "isig", "icanon", "iexten", "echo", "echoe", "echok",
        "echoctl", "echoke", "nl0", "cr0", "tab0", "bs0", "vt0", "ff0",
    ] {
        set(t, n, true);
    }
    for n in [
        "ignbrk", "inlcr", "igncr", "echonl", "noflsh", "ixoff", "iutf8", "iuclc", "ixany", "xcase", "olcuc", "ocrnl",
        "ofill", "onocr", "onlret", "tostop", "ofdel", "echoprt", "extproc", "flusho",
    ] {
        set(t, n, false);
    }
    for &(i, v) in SANE_CC {
        t.cc[i] = v;
    }
    t.cc[VMIN] = 1;
    t.cc[VTIME] = 0;
}

/// Is `t` what `sane` (plus ixon and cs8, which sane leaves alone) would
/// make it, for the flag `fl`?
fn default_set(fl: &Flag) -> bool {
    matches!(
        fl.name,
        "cs8"
            | "cread"
            | "brkint"
            | "icrnl"
            | "ixon"
            | "imaxbel"
            | "opost"
            | "onlcr"
            | "nl0"
            | "cr0"
            | "tab0"
            | "bs0"
            | "vt0"
            | "ff0"
            | "isig"
            | "icanon"
            | "iexten"
            | "echo"
            | "echoe"
            | "echok"
            | "echoctl"
            | "echoke"
    )
}

fn char_name(c: u8) -> String {
    match c {
        0 => String::from("<undef>"),
        127 => String::from("^?"),
        c if c < 32 => alloc::format!("^{}", (c + b'@') as char),
        c if c >= 128 => {
            let low = c & 0x7f;
            if low < 32 { alloc::format!("M-^{}", (low + b'@') as char) } else { alloc::format!("M-{}", low as char) }
        }
        c => alloc::format!("{}", c as char),
    }
}

fn parse_char(v: &[u8]) -> Option<u8> {
    match v {
        b"^-" | b"undef" => Some(0),
        b"^?" => Some(127),
        [b'^', c] => Some(c.to_ascii_uppercase() & 0x1f),
        [c] => Some(*c),
        _ => {
            let s = core::str::from_utf8(v).ok()?;
            let n = if let Some(h) = s.strip_prefix("0x") {
                u32::from_str_radix(h, 16).ok()?
            } else if s.len() > 1 && s.starts_with('0') {
                u32::from_str_radix(&s[1..], 8).ok()?
            } else {
                s.parse().ok()?
            };
            u8::try_from(n).ok()
        }
    }
}

fn speed_of(bits: u32) -> u32 {
    SPEEDS.iter().find(|(_, b)| *b == bits).map(|(s, _)| *s).unwrap_or(0)
}

/// The output speed.
fn speed(t: &term::Termios) -> u32 {
    speed_of(t.cflag & CBAUD)
}

/// The input speed.
fn ispeed(t: &term::Termios) -> u32 {
    match (t.cflag >> IBSHIFT) & CBAUD {
        0 => speed(t),
        b => speed_of(b),
    }
}

/// `speed N baud;`, or `ispeed I baud; ospeed O baud;` when they differ.
fn speeds(t: &term::Termios) -> String {
    if ispeed(t) == speed(t) {
        alloc::format!("speed {} baud;", speed(t))
    } else {
        alloc::format!("ispeed {} baud; ospeed {} baud;", ispeed(t), speed(t))
    }
}

/// Lines no wider than the output allows, items separated by spaces.
struct Wrapper {
    width: usize,
    line: String,
}

impl Wrapper {
    fn push(&mut self, item: &str) {
        if !self.line.is_empty() && self.line.len() + 1 + item.len() >= self.width {
            self.flush();
        }
        if !self.line.is_empty() {
            self.line.push(' ');
        }
        self.line.push_str(item);
    }

    fn flush(&mut self) {
        if !self.line.is_empty() {
            println!("{}", self.line);
            self.line.clear();
        }
    }
}

fn show(fd: i32, t: &term::Termios, all: bool) {
    let width =
        if term::isatty(io::STDOUT) { term::size(io::STDOUT).map(|(_, c)| usize::from(c)).unwrap_or(80) } else { 80 };
    let mut w = Wrapper { width, line: String::new() };
    if all {
        let (rows, cols) = term::size(fd).unwrap_or((0, 0));
        w.push(&alloc::format!("{} rows {rows}; columns {cols}; line = {};", speeds(t), t.line));
    } else {
        w.push(&alloc::format!("{} line = {};", speeds(t), t.line));
    }
    w.flush();
    let icanon = t.lflag & 2 != 0;
    for &(name, i) in CHARS {
        let def = SANE_CC.iter().find(|(k, _)| *k == i).map(|(_, v)| *v).unwrap_or(0);
        if all || t.cc[i] != def {
            w.push(&alloc::format!("{name} = {};", char_name(t.cc[i])));
        }
    }
    if all || !icanon {
        w.push(&alloc::format!("min = {}; time = {};", t.cc[VMIN], t.cc[VTIME]));
    }
    w.flush();
    // Each flag word starts a line; the input flags' list breaks before
    // iuclc in GNU's layout, as do the local flags before echoctl.
    let mut prev = None;
    for fl in FLAGS {
        if prev.is_some_and(|p| p != fl.field) || (all && matches!(fl.name, "iuclc" | "echoctl")) {
            w.flush();
        }
        prev = Some(fl.field);
        let on = is_set(t, fl);
        if fl.choice {
            if on && (all || !default_set(fl)) {
                w.push(fl.name);
            }
        } else if all || on != default_set(fl) {
            w.push(&alloc::format!("{}{}", if on { "" } else { "-" }, fl.name));
        }
    }
    w.flush();
}

fn invalid(a: &[u8]) -> i32 {
    error(format_args!("invalid argument '{}'", lossy(a)));
    slate_rt::eprintln!("Try '{} --help' for more information.", slate_rt::prog_name());
    1
}

/// Apply one setting (and its arguments from `rest`); returns how many
/// extra words it took, or None if it's not a setting.
fn apply(t: &mut term::Termios, fd: i32, a: &str, rest: &[Vec<u8>]) -> Result<usize, i32> {
    let (on, name) = match a.strip_prefix('-') {
        Some(n) => (false, n),
        None => (true, a),
    };
    if set(t, name, on) {
        return Ok(0);
    }
    if on && let Some(&(_, idx)) = CHARS.iter().find(|(n, _)| *n == name) {
        let Some(v) = rest.first() else {
            error(format_args!("missing argument to '{name}'"));
            return Err(1);
        };
        t.cc[idx] = parse_char(v).ok_or_else(|| invalid(v))?;
        return Ok(1);
    }
    let num_arg = |what: &str| -> Result<u32, i32> {
        let Some(v) = rest.first() else {
            error(format_args!("missing argument to '{what}'"));
            return Err(1);
        };
        parse_num::<u32>(v).ok_or_else(|| invalid(v))
    };
    match (on, name) {
        (true, "min") => t.cc[VMIN] = num_arg(name)? as u8,
        (true, "time") => t.cc[VTIME] = num_arg(name)? as u8,
        (true, "rows" | "cols" | "columns") => {
            let n = num_arg(name)? as u16;
            let (r, c) = term::size(fd).unwrap_or((0, 0));
            let (r, c) = if name == "rows" { (n, c) } else { (r, n) };
            if let Err(e) = term::set_size(fd, r, c) {
                error(format_args!("{e}"));
                return Err(1);
            }
        }
        (true, "ispeed" | "ospeed") => {
            let s = num_arg(name)?;
            let Some(&(_, b)) = SPEEDS.iter().find(|(sp, _)| *sp == s) else { return Err(invalid(&rest[0])) };
            if name == "ospeed" {
                t.cflag = (t.cflag & !CBAUD) | b;
            } else {
                // 0: the output speed.
                let b = if b == 0 { t.cflag & CBAUD } else { b };
                t.cflag = (t.cflag & !(CBAUD << IBSHIFT)) | b << IBSHIFT;
            }
        }
        (true, "line") => {
            // Out of range, GNU's stty warns (once as it checks the
            // arguments, once as it applies them) and goes on.
            let n = num_arg(name)?;
            match u8::try_from(n) {
                Ok(l) => t.line = l,
                Err(_) => {
                    for _ in 0..2 {
                        error(format_args!("invalid line discipline '{n}': Value too large for defined data type"));
                    }
                }
            }
        }
        (true, "sane") => {
            sane(t);
            return Ok(0);
        }
        (true, "raw") | (false, "cooked") => {
            for n in [
                "ignbrk", "brkint", "ignpar", "parmrk", "inpck", "istrip", "inlcr", "igncr", "icrnl", "ixon", "ixoff",
                "iuclc", "ixany", "imaxbel", "opost", "isig", "icanon", "xcase",
            ] {
                set(t, n, false);
            }
            t.cc[VMIN] = 1;
            t.cc[VTIME] = 0;
            return Ok(0);
        }
        (false, "raw") | (true, "cooked") => {
            for n in ["brkint", "ignpar", "istrip", "icrnl", "ixon", "opost", "isig", "icanon"] {
                set(t, n, true);
            }
            return Ok(0);
        }
        (_, "cbreak") => {
            set(t, "icanon", !on);
            return Ok(0);
        }
        (_, "nl") => {
            set(t, "icrnl", !on);
            set(t, "onlcr", !on);
            if !on {
                set(t, "inlcr", false);
                set(t, "igncr", false);
                set(t, "ocrnl", false);
                set(t, "onlret", false);
            }
            return Ok(0);
        }
        (true, "evenp" | "parity") => {
            set(t, "parenb", true);
            set(t, "parodd", false);
            set(t, "cs7", true);
        }
        (true, "oddp") => {
            set(t, "parenb", true);
            set(t, "parodd", true);
            set(t, "cs7", true);
        }
        (false, "evenp" | "oddp" | "parity") => {
            set(t, "parenb", false);
            set(t, "cs8", true);
        }
        (_, "pass8") => {
            set(t, "parenb", !on);
            set(t, "istrip", !on);
            set(t, if on { "cs8" } else { "cs7" }, true);
        }
        (_, "litout") => {
            set(t, "parenb", !on);
            set(t, "istrip", !on);
            set(t, "opost", !on);
            set(t, if on { "cs8" } else { "cs7" }, true);
        }
        (_, "tabs") => {
            set(t, if on { "tab0" } else { "tab3" }, true);
        }
        (true, "ek") => {
            t.cc[2] = 0x7f;
            t.cc[3] = 0x15;
        }
        (true, "crt") => {
            for n in ["echoe", "echoctl", "echoke"] {
                set(t, n, true);
            }
        }
        (true, "dec") => {
            for n in ["echoe", "echoctl", "echoke"] {
                set(t, n, true);
            }
            set(t, "ixany", false);
            t.cc[0] = 3;
            t.cc[2] = 0x7f;
            t.cc[3] = 0x15;
        }
        (true, s) if s.bytes().all(|b| b.is_ascii_digit()) => {
            let n: u32 = s.parse().unwrap_or(u32::MAX);
            let Some(&(_, b)) = SPEEDS.iter().find(|(sp, _)| *sp == n) else { return Err(invalid(a.as_bytes())) };
            // Both speeds.
            t.cflag = (t.cflag & !(CBAUD | CBAUD << IBSHIFT)) | b | b << IBSHIFT;
        }
        _ => return Err(invalid(a.as_bytes())),
    }
    Ok(usize::from(matches!(name, "min" | "time" | "rows" | "cols" | "columns" | "ispeed" | "ospeed" | "line")))
}

/// The control characters `-g` lists: C's NCCS (32, GNU's count), the
/// kernel's 19 then zeros.
const SAVED_CHARS: usize = 32;

/// `stty -g` output read back: hex fields separated by colons, with 32
/// control characters (or the kernel's 19, as earlier Slate printed).
fn parse_saved(s: &[u8]) -> Option<term::Termios> {
    let parts: Vec<&[u8]> = s.split(|&c| c == b':').collect();
    if parts.len() != 4 + SAVED_CHARS && parts.len() != 4 + 19 {
        return None;
    }
    let hex = |p: &[u8]| u32::from_str_radix(core::str::from_utf8(p).ok()?, 16).ok();
    let mut t = term::Termios {
        iflag: hex(parts[0])?,
        oflag: hex(parts[1])?,
        cflag: hex(parts[2])?,
        lflag: hex(parts[3])?,
        ..Default::default()
    };
    for (i, p) in parts[4..].iter().enumerate() {
        let v = u8::try_from(hex(p)?).ok()?;
        if let Some(c) = t.cc.get_mut(i) {
            *c = v;
        }
    }
    Some(t)
}

pub fn main(args: &[Vec<u8>]) -> i32 {
    let mut fd = io::STDIN;
    let mut dev: Option<Vec<u8>> = None;
    let (mut all, mut save) = (false, false);
    let mut settings: Vec<Vec<u8>> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        match a.as_slice() {
            b"-a" | b"--all" => all = true,
            b"-g" | b"--save" => save = true,
            b"-F" | b"--file" => {
                i += 1;
                dev = args.get(i).cloned();
            }
            x if x.starts_with(b"--file=") => dev = Some(x[7..].to_vec()),
            x if x.starts_with(b"-F") && x.len() > 2 => dev = Some(x[2..].to_vec()),
            _ => settings.push(a.clone()),
        }
        i += 1;
    }
    let name = match &dev {
        Some(d) => match fs::open(d, fs::O_RDONLY | fs::O_NONBLOCK | fs::O_NOCTTY | fs::O_CLOEXEC, 0) {
            Ok(f) => {
                // Opened without waiting for the line (a modem's carrier),
                // then used as usual (as GNU's stty does).
                if let Ok(fl) = slate_rt::process::fcntl(f, slate_rt::process::F_GETFL, 0) {
                    let _ = slate_rt::process::fcntl(f, slate_rt::process::F_SETFL, fl & !(fs::O_NONBLOCK as usize));
                }
                fd = f;
                d.clone()
            }
            Err(e) => {
                error(format_args!("{}: {e}", lossy(d)));
                return 1;
            }
        },
        None => b"standard input".to_vec(),
    };
    if (all || save) && !settings.is_empty() {
        error("when specifying an output style, modes may not be set");
        return 1;
    }
    if all && save {
        error("the options for verbose and stty-readable output styles are mutually exclusive");
        return 1;
    }
    let mut t = match term::get(fd) {
        Ok(t) => t,
        Err(e) => {
            error(format_args!("'{}': {e}", lossy(&name)));
            return 1;
        }
    };
    if save {
        print!("{:x}:{:x}:{:x}:{:x}", t.iflag, t.oflag, t.cflag, t.lflag);
        for i in 0..SAVED_CHARS {
            print!(":{:x}", t.cc.get(i).copied().unwrap_or(0));
        }
        println!();
        io::flush_stdout();
        return 0;
    }
    if settings.is_empty() {
        show(fd, &t, all);
        io::flush_stdout();
        return 0;
    }
    let orig = t;
    let mut k = 0;
    while k < settings.len() {
        let s = String::from_utf8_lossy(&settings[k]).into_owned();
        match s.as_str() {
            "size" => {
                let (r, c) = term::size(fd).unwrap_or((0, 0));
                println!("{r} {c}");
            }
            "speed" if ispeed(&t) == speed(&t) => println!("{}", speed(&t)),
            "speed" => println!("{} {}", ispeed(&t), speed(&t)),
            _ => {
                if s.contains(':')
                    && let Some(saved) = parse_saved(settings[k].as_slice())
                {
                    t = saved;
                } else {
                    match apply(&mut t, fd, &s, &settings[k + 1..]) {
                        Ok(n) => k += n,
                        Err(code) => {
                            io::flush_stdout();
                            return code;
                        }
                    }
                }
            }
        }
        k += 1;
    }
    if t != orig
        && let Err(e) = term::set(fd, &t, true)
    {
        error(format_args!("'{}': {e}", lossy(&name)));
        return 1;
    }
    io::flush_stdout();
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chars_and_saved_state() {
        assert_eq!(char_name(3), "^C");
        assert_eq!(char_name(0x1c), "^\\");
        assert_eq!(char_name(127), "^?");
        assert_eq!(char_name(0), "<undef>");
        assert_eq!(parse_char(b"^x"), Some(0x18));
        assert_eq!(parse_char(b"undef"), Some(0));
        assert_eq!(parse_char(b"0x7f"), Some(127));
        let t = parse_saved(b"500:5:bf:8a3b:3:1c:7f:15:4:0:1:0:11:13:1a:0:12:f:17:16:0:0:0").unwrap();
        assert_eq!((t.iflag, t.oflag, t.cflag, t.lflag, t.cc[0], t.cc[6]), (0x500, 5, 0xbf, 0x8a3b, 3, 1));
        assert_eq!(speed(&t), 38400);
    }

    #[test]
    fn settings() {
        let mut t = term::Termios::default();
        sane(&mut t);
        set(&mut t, "cs8", true);
        set(&mut t, "ixon", true);
        assert!(FLAGS.iter().all(|fl| is_set(&t, fl) == default_set(fl)));
        apply(&mut t, -1, "raw", &[]).unwrap();
        assert_eq!(t.lflag & 2, 0);
        apply(&mut t, -1, "-raw", &[]).unwrap();
        assert_ne!(t.lflag & 2, 0);
        assert_eq!(apply(&mut t, -1, "intr", &[b"^X".to_vec()]), Ok(1));
        assert_eq!(t.cc[0], 0x18);
    }
}
