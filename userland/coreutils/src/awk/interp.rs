// SPDX-License-Identifier: MIT OR Apache-2.0

//! Running an awk program: records and fields, variables and arrays,
//! patterns and actions, getline, output redirections and the built-in
//! functions (XCU awk, "Description" through "Functions").

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use slate_regex::{Options, Regex, Syntax};
use slate_rt::{fs, io, process};

use super::big::Big;
use super::math;
use super::parse::*;
use super::value::{self, Value, num_to_str, sprintf};

/// An array: its elements are values, or (gawk's arrays of arrays)
/// arrays.
pub type Array = BTreeMap<Vec<u8>, Cell>;

#[derive(Clone, Debug)]
pub enum Cell {
    Val(Value),
    Arr(Rc<RefCell<Array>>),
}

impl From<Value> for Cell {
    fn from(v: Value) -> Cell {
        Cell::Val(v)
    }
}

impl Cell {
    /// The value, where a scalar is wanted (a subarray reads as nothing).
    pub fn val(&self) -> Value {
        match self {
            Cell::Val(v) => v.clone(),
            Cell::Arr(_) => Value::Uninit,
        }
    }

    pub fn text(&self, convfmt: &[u8]) -> Vec<u8> {
        self.val().text(convfmt)
    }
}

/// A directory's entries as readdir's records (`.` and `..` too), on a
/// pipe a child writes them into.
fn listing(dir: &[u8]) -> Option<i32> {
    let mut text = Vec::new();
    let me = fs::stat(dir).ok()?;
    let parent = fs::stat(&[dir, b"/.."].concat()).map_or(me.ino, |s| s.ino);
    let mut entries = alloc::vec![(me.ino, b".".to_vec(), b'd'), (parent, b"..".to_vec(), b'd')];
    for e in fs::read_dir(dir).ok()? {
        let t = match e.kind {
            4 => b'd',
            8 => b'f',
            10 => b'l',
            2 => b'c',
            6 => b'b',
            1 => b'p',
            12 => b's',
            _ => b'u',
        };
        entries.push((e.ino, e.name, t));
    }
    for (ino, name, t) in entries {
        text.extend_from_slice(alloc::format!("{ino}/").as_bytes());
        text.extend_from_slice(&name);
        text.extend_from_slice(&[b'/', t, b'\n']);
    }
    let (r, w) = process::pipe(fs::O_CLOEXEC).ok()?;
    match process::fork().ok()? {
        0 => {
            let _ = io::close(r);
            let _ = io::write_all(w, &text);
            process::exit_now(0);
        }
        _ => {
            let _ = io::close(w);
            Some(r)
        }
    }
}

/// Whether `name` is a built-in extension's function (`@load`).
fn is_extension(name: &str) -> bool {
    super::lex::EXTENSIONS.iter().any(|(_, f)| f.contains(&name))
}

/// Non-local control flow.
#[derive(Debug)]
pub enum Flow {
    Next,
    NextFile,
    Exit,
    Return(Value),
    Break,
    Continue,
    Fatal(String),
}

type Res<T> = Result<T, Flow>;

fn fatal<T>(m: impl Into<String>) -> Res<T> {
    Err(Flow::Fatal(m.into()))
}

/// A record reader with awk's RS rules.
struct Records {
    fd: i32,
    reader: io::Reader,
    /// The whole rest of the input (for a regex RS).
    buf: Option<(Vec<u8>, usize)>,
    /// A line read ahead in paragraph mode.
    pending: Option<Vec<u8>>,
    eof: bool,
}

impl Records {
    fn new(fd: i32) -> Records {
        Records { fd, reader: io::Reader::new(fd), buf: None, pending: None, eof: false }
    }

    /// The next record and its terminator (RT).
    fn next(&mut self, rs: &[u8], re_cache: &mut dyn FnMut(&[u8]) -> Option<Rc<Regex>>) -> Option<(Vec<u8>, Vec<u8>)> {
        if self.eof {
            return None;
        }
        if rs.len() == 1 {
            return match self.reader.split(rs[0]) {
                Ok(Some(mut l)) => {
                    let mut rt = Vec::new();
                    if l.last() == Some(&rs[0]) {
                        l.pop();
                        rt.push(rs[0]);
                    }
                    Some((l, rt))
                }
                _ => {
                    self.eof = true;
                    None
                }
            };
        }
        if rs.is_empty() {
            // Paragraph mode: blank lines separate records.
            let mut lines: Vec<Vec<u8>> = Vec::new();
            let read_line = |s: &mut Records| -> Option<Vec<u8>> {
                if let Some(p) = s.pending.take() {
                    return Some(p);
                }
                match s.reader.line() {
                    Ok(Some(mut l)) => {
                        if l.last() == Some(&b'\n') {
                            l.pop();
                        }
                        Some(l)
                    }
                    _ => None,
                }
            };
            loop {
                match read_line(self) {
                    None => {
                        self.eof = true;
                        break;
                    }
                    Some(l) if l.is_empty() => {
                        if lines.is_empty() {
                            continue;
                        }
                        // Swallow further blank lines.
                        loop {
                            match read_line(self) {
                                Some(l) if l.is_empty() => continue,
                                Some(l) => {
                                    self.pending = Some(l);
                                    break;
                                }
                                None => {
                                    self.eof = true;
                                    break;
                                }
                            }
                        }
                        break;
                    }
                    Some(l) => lines.push(l),
                }
            }
            if lines.is_empty() {
                return None;
            }
            return Some((lines.join(&b'\n'), b"\n\n".to_vec()));
        }
        // A regular expression separates records (gawk).
        if self.buf.is_none() {
            let mut all = Vec::new();
            while let Ok(c) = self.reader.chunk(64 * 1024) {
                if c.is_empty() {
                    break;
                }
                all.extend_from_slice(&c);
            }
            self.buf = Some((all, 0));
        }
        let re = re_cache(rs)?;
        let (buf, pos) = self.buf.as_mut()?;
        if *pos >= buf.len() {
            self.eof = true;
            return None;
        }
        let start = *pos;
        let mut search = start;
        loop {
            match re.find_at(buf, search).and_then(|c| c[0]) {
                Some((a, b)) if b > a => {
                    let rec = buf[start..a].to_vec();
                    let rt = buf[a..b].to_vec();
                    *pos = b;
                    return Some((rec, rt));
                }
                Some((a, _)) if a < buf.len() => search = a + 1,
                _ => {
                    let rec = buf[start..].to_vec();
                    *pos = buf.len();
                    return Some((rec, Vec::new()));
                }
            }
        }
    }
}

enum Output {
    File(i32),
    Pipe(i32, i32),
}

pub struct Interp<'p> {
    prog: &'p Program,
    globals: Vec<Cell>,
    frames: Vec<Vec<Cell>>,
    /// For each frame's parameters, the caller's variable an unset
    /// argument came from: reading the parameter marks it "unassigned"
    /// (as gawk's typeof was seen to).
    sources: Vec<Vec<Option<Var>>>,
    record: Vec<u8>,
    fields: Vec<Vec<u8>>,
    split_done: bool,
    /// How the current record splits (FS, FIELDWIDTHS or FPAT when it
    /// was read).
    record_split: Splitter,
    /// Which of FS, FIELDWIDTHS and FPAT was assigned last, and
    /// FIELDWIDTHS read.
    split_by: usize,
    widths: Vec<(usize, Option<usize>)>,
    regexes: Vec<Rc<Regex>>,
    /// The program's regexes compiled to ignore case, when IGNORECASE
    /// first needs them.
    regexes_icase: Vec<Option<Rc<Regex>>>,
    dyn_re: BTreeMap<Vec<u8>, Rc<Regex>>,
    /// `-M`: integers exact however large.
    bignum: bool,
    /// `-i inplace`: the saved standard output and the file being made.
    inplace: Option<(i32, Vec<u8>)>,
    /// A UTF-8 locale: length, substr, index and match count characters
    /// (as gawk does there), not bytes.
    utf8: bool,
    ranges: Vec<bool>,
    outputs: Vec<(Vec<u8>, Output)>,
    inputs: Vec<(Vec<u8>, Records, i32)>,
    main: Option<Records>,
    argi: usize,
    used_file: bool,
    rand_state: u64,
    seed: f64,
    pub exit_code: i32,
    out: Vec<u8>,
    depth: usize,
}

/// An index that gawk keeps as an integer (0 to 2^31-1, as written by
/// converting the number): those come last, ascending, in a plain `for in`.
fn integer_key(k: &[u8]) -> Option<u32> {
    if k.is_empty() || k.len() > 10 || !k.iter().all(u8::is_ascii_digit) || (k.len() > 1 && k[0] == b'0') {
        return None;
    }
    let n: u64 = core::str::from_utf8(k).ok()?.parse().ok()?;
    (n < 1 << 31).then_some(n as u32)
}

/// How a record splits into fields.
#[derive(Clone, Debug)]
enum Splitter {
    Fs(Vec<u8>),
    Widths(Vec<(usize, Option<usize>)>),
    Pat(Vec<u8>),
}

/// FIELDWIDTHS (gawk manual, "Reading Fixed-Width Data"): widths apart by
/// spaces, each perhaps after `skip:`, and a last `*` for the rest.
fn parse_widths(text: &[u8]) -> Result<Vec<(usize, Option<usize>)>, String> {
    let mut out = Vec::new();
    let items: Vec<&[u8]> = text.split(|c| c.is_ascii_whitespace()).filter(|w| !w.is_empty()).collect();
    for (n, item) in items.iter().enumerate() {
        let num = |s: &[u8]| -> Option<usize> {
            if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
                return None;
            }
            core::str::from_utf8(s).ok()?.parse().ok()
        };
        let (skip, width) = match item.iter().position(|&c| c == b':') {
            Some(i) => (num(&item[..i]), &item[i + 1..]),
            None => (Some(0), &item[..]),
        };
        let width = if width == b"*" && n + 1 == items.len() { Some(None) } else { num(width).map(Some) };
        match (skip, width) {
            (Some(skip), Some(width)) => out.push((skip, width)),
            _ => {
                let rest = items[n..].join(&b' ');
                return Err(alloc::format!(
                    "invalid FIELDWIDTHS value, for field {}, near `{}'",
                    n + 1,
                    String::from_utf8_lossy(&rest)
                ));
            }
        }
    }
    Ok(out)
}

fn split_widths(text: &[u8], widths: &[(usize, Option<usize>)]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;
    for &(skip, width) in widths {
        pos += skip;
        if pos >= text.len() {
            break;
        }
        let end = width.map_or(text.len(), |w| (pos + w).min(text.len()));
        out.push(text[pos..end].to_vec());
        pos = end;
    }
    out
}

/// Fields that match `re` and the separators around them (FPAT and
/// patsplit): an empty match right after a non-empty one does not count,
/// as gawk was seen to do. `seps[0]` comes before the first field.
fn pattern_split(text: &[u8], re: &Regex) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let (mut fields, mut seps) = (Vec::new(), Vec::new());
    if text.is_empty() {
        return (fields, seps);
    }
    let (mut pos, mut prev_end, mut nonempty_end) = (0, 0, None);
    while pos <= text.len() {
        let Some((a, b)) = re.find_at(text, pos).and_then(|c| c[0]) else { break };
        if a == b && nonempty_end == Some(a) {
            pos = a + 1;
            continue;
        }
        seps.push(text[prev_end..a].to_vec());
        fields.push(text[a..b].to_vec());
        prev_end = b;
        if b > a {
            nonempty_end = Some(b);
            pos = b;
        } else {
            pos = a + 1;
        }
    }
    seps.push(text[prev_end..].to_vec());
    (fields, seps)
}

/// gawk's strtonum: `0x` hexadecimal, a leading 0 octal (unless the
/// digits or what follows make it decimal), else decimal.
fn strtonum(t: &[u8]) -> f64 {
    if let Some(hex) = t.strip_prefix(b"0x").or_else(|| t.strip_prefix(b"0X")) {
        let digits: Vec<u8> = hex.iter().copied().take_while(u8::is_ascii_hexdigit).collect();
        return digits.iter().fold(0.0, |n, &c| n * 16.0 + f64::from((c as char).to_digit(16).unwrap_or(0)));
    }
    if t.len() > 1 && t[0] == b'0' && t[1].is_ascii_digit() {
        let run: Vec<u8> = t.iter().copied().take_while(u8::is_ascii_digit).collect();
        let after = t.get(run.len()).copied();
        if run.iter().all(|&c| c < b'8') && !matches!(after, Some(b'.' | b'e' | b'E')) {
            return run.iter().fold(0.0, |n, &c| n * 8.0 + f64::from(c - b'0'));
        }
    }
    value::str_to_num(t) + 0.0
}

/// mktime's "YYYY MM DD HH MM SS [DST]": numbers with optional signs,
/// as many as could be read; None with fewer than six.
fn mktime_fields(t: &[u8]) -> Option<([i64; 6], i64)> {
    let mut nums = Vec::new();
    let mut i = 0;
    while nums.len() < 7 {
        while t.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        let start = i;
        if matches!(t.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let digits = i;
        while t.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == digits {
            break;
        }
        nums.push(core::str::from_utf8(&t[start..i]).ok()?.parse::<i64>().ok()?);
    }
    if nums.len() < 6 {
        return None;
    }
    Some(([nums[0], nums[1], nums[2], nums[3], nums[4], nums[5]], nums.get(6).copied().unwrap_or(-1)))
}

/// gawk's mktime: the local time (or UTC) given as "YYYY MM DD HH MM SS
/// [DST]", out-of-range parts carried over; -1 if it can't be read. A
/// DST of 0 or more says whether summer time applies.
fn mktime(spec: &[u8], utc: bool) -> i64 {
    let Some(([y, mo, d, h, mi, sec], dst)) = mktime_fields(spec) else { return -1 };
    let months = y * 12 + (mo - 1);
    let (year, month) = (months.div_euclid(12), months.rem_euclid(12) + 1);
    let first = slate_rt::time::Tm { year, month: month as u32, day: 1, ..slate_rt::time::gmtime(0) };
    let wall = slate_rt::time::timegm(&first) + (d - 1) * 86_400 + h * 3600 + mi * 60 + sec;
    if utc {
        return wall;
    }
    let mut t = slate_rt::tz::timelocal(&slate_rt::time::gmtime(wall));
    if dst >= 0 {
        let summer = slate_rt::tz::is_summer(t);
        if dst > 0 && !summer {
            t -= 3600;
        } else if dst == 0 && summer {
            t += 3600;
        }
    }
    t
}

/// `items` into array `a` from index `first` (split, patsplit).
fn fill(a: &Rc<RefCell<Array>>, items: Vec<Vec<u8>>, first: usize) {
    let mut a = a.borrow_mut();
    a.clear();
    for (i, p) in items.into_iter().enumerate() {
        a.insert(alloc::format!("{}", i + first).into_bytes(), Cell::from(Value::from_input(p)));
    }
}

/// An array element: index and value.
type Item = (Vec<u8>, Value);

fn lossy_str(s: &[u8]) -> String {
    String::from_utf8_lossy(s).into_owned()
}

fn key_text(v: &Value, convfmt: &[u8]) -> Vec<u8> {
    match v {
        Value::Num(n) => num_to_str(*n, convfmt),
        other => other.text(convfmt),
    }
}

/// Split `text` into fields with FS rules (XCU awk, "Regular Expressions"
/// and "Variables and Special Variables").
pub fn split_with(
    text: &[u8],
    fs: &[u8],
    paragraph: bool,
    re: &mut dyn FnMut(&[u8]) -> Option<Rc<Regex>>,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    split_into(text, fs, paragraph, re, &mut out);
    out
}

/// [`split_with`] into `out`, whose fields' buffers are reused (the
/// record's fields, split again for each record).
fn split_into(
    text: &[u8],
    fs: &[u8],
    paragraph: bool,
    re: &mut dyn FnMut(&[u8]) -> Option<Rc<Regex>>,
    out: &mut Vec<Vec<u8>>,
) {
    if fs == b" " {
        let ws = |c: &u8| matches!(c, b' ' | b'\t' | b'\n');
        let mut n = 0;
        for f in text.split(ws).filter(|f| !f.is_empty()) {
            if n < out.len() {
                out[n].clear();
                out[n].extend_from_slice(f);
            } else {
                out.push(f.to_vec());
            }
            n += 1;
        }
        out.truncate(n);
        return;
    }
    *out = split_other(text, fs, paragraph, re);
}

fn split_other(
    text: &[u8],
    fs: &[u8],
    paragraph: bool,
    re: &mut dyn FnMut(&[u8]) -> Option<Rc<Regex>>,
) -> Vec<Vec<u8>> {
    if text.is_empty() {
        return Vec::new();
    }
    if paragraph && fs.len() == 1 {
        // Newline always separates fields too.
        return text.split(|&c| c == fs[0] || c == b'\n').map(<[u8]>::to_vec).collect();
    }
    if fs.is_empty() {
        return text.iter().map(|&c| alloc::vec![c]).collect();
    }
    if fs.len() == 1 && fs[0] != b'\\' {
        return text.split(|&c| c == fs[0]).map(<[u8]>::to_vec).collect();
    }
    let pat = if paragraph { [b"(".as_slice(), fs, b")|\n"].concat() } else { fs.to_vec() };
    let Some(r) = re(&pat) else { return alloc::vec![text.to_vec()] };
    let mut out = Vec::new();
    let mut start = 0;
    let mut pos = 0;
    while pos <= text.len() {
        match r.find_at(text, pos).and_then(|c| c[0]) {
            Some((a, b)) if b > a => {
                out.push(text[start..a].to_vec());
                start = b;
                pos = b;
            }
            Some((a, _)) if a < text.len() => pos = a + 1,
            _ => break,
        }
    }
    out.push(text[start..].to_vec());
    out
}

impl<'p> Interp<'p> {
    pub fn new(prog: &'p Program, argv: &[Vec<u8>], assigns: &[(Vec<u8>, Vec<u8>)]) -> Result<Interp<'p>, String> {
        let mut regexes = Vec::new();
        for r in &prog.regexes {
            let opts = Options {
                syntax: Syntax::Extended,
                escapes: true,
                utf8: crate::util::utf8_locale(),
                ..Options::default()
            };
            regexes.push(Rc::new(
                Regex::new(r, opts)
                    .map_err(|e| alloc::format!("regular expression /{}/: {e}", String::from_utf8_lossy(r)))?,
            ));
        }
        let mut it = Interp {
            prog,
            globals: alloc::vec![Cell::Val(Value::Uninit); prog.globals.len()],
            frames: Vec::new(),
            sources: Vec::new(),
            record: Vec::new(),
            fields: Vec::new(),
            split_done: true,
            record_split: Splitter::Fs(b" ".to_vec()),
            split_by: FS,
            widths: Vec::new(),
            regexes_icase: alloc::vec![None; regexes.len()],
            regexes,
            dyn_re: BTreeMap::new(),
            inplace: None,
            bignum: value::BIGNUM.load(core::sync::atomic::Ordering::Relaxed),
            utf8: {
                let u = crate::util::utf8_locale();
                value::UTF8.store(u, core::sync::atomic::Ordering::Relaxed);
                u
            },
            ranges: alloc::vec![false; prog.rules.len()],
            outputs: Vec::new(),
            inputs: Vec::new(),
            main: None,
            argi: 1,
            used_file: false,
            rand_state: 0x2545_F491_4F6C_DD1D,
            seed: 0.0,
            exit_code: 0,
            out: Vec::new(),
            depth: 0,
        };
        let s = |t: &str| Cell::Val(Value::Str(t.as_bytes().to_vec()));
        it.globals[FS] = s(" ");
        it.globals[OFS] = s(" ");
        it.globals[ORS] = s("\n");
        it.globals[RS] = s("\n");
        it.globals[SUBSEP] = s("\x1c");
        it.globals[CONVFMT] = s("%.6g");
        it.globals[OFMT] = s("%.6g");
        it.globals[NR] = Cell::Val(Value::Num(0.0));
        it.globals[FNR] = Cell::Val(Value::Num(0.0));
        it.globals[RSTART] = Cell::Val(Value::Num(0.0));
        it.globals[RLENGTH] = Cell::Val(Value::Num(-1.0));
        it.globals[FILENAME] = Cell::Val(Value::Uninit);
        let mut env = Array::new();
        for e in slate_rt::env::vars() {
            if let Some(eq) = e.iter().position(|&c| c == b'=') {
                env.insert(e[..eq].to_vec(), Cell::from(Value::from_input(e[eq + 1..].to_vec())));
            }
        }
        it.globals[ENVIRON] = Cell::Arr(Rc::new(RefCell::new(env)));
        // gawk's PROCINFO (gawk manual, "Built-in Variables That Convey
        // Information"), the elements that apply here.
        let mut info = Array::new();
        let n = |x: i64| Value::Num(x as f64);
        info.insert(b"pid".to_vec(), Cell::from(n(process::getpid().into())));
        info.insert(b"ppid".to_vec(), Cell::from(n(process::getppid().into())));
        info.insert(b"pgrpid".to_vec(), Cell::from(n(process::getpgrp().into())));
        info.insert(b"uid".to_vec(), Cell::from(n(process::getuid().into())));
        info.insert(b"euid".to_vec(), Cell::from(n(process::geteuid().into())));
        info.insert(b"gid".to_vec(), Cell::from(n(process::getgid().into())));
        info.insert(b"egid".to_vec(), Cell::from(n(process::getegid().into())));
        info.insert(b"FS".to_vec(), Cell::from(Value::Str(b"FS".to_vec())));
        info.insert(b"platform".to_vec(), Cell::from(Value::Str(b"posix".to_vec())));
        info.insert(b"strftime".to_vec(), Cell::from(Value::Str(b"%a %b %e %H:%M:%S %Z %Y".to_vec())));
        info.insert(b"version".to_vec(), Cell::from(Value::Str(super::VERSION.to_vec())));
        it.globals[PROCINFO] = Cell::Arr(Rc::new(RefCell::new(info)));
        let mut av = Array::new();
        for (i, a) in argv.iter().enumerate() {
            av.insert(alloc::format!("{i}").into_bytes(), Cell::from(Value::from_input(a.clone())));
        }
        it.globals[ARGV] = Cell::Arr(Rc::new(RefCell::new(av)));
        it.globals[ARGC] = Cell::Val(Value::Num(argv.len() as f64));
        // fnmatch's flag values, in FNM (as gawk's extension was seen to
        // set them).
        if prog.loaded.contains(&"fnmatch")
            && let Some(i) = prog.globals.iter().position(|g| g == b"FNM")
        {
            let flags = [
                ("PATHNAME", 1),
                ("FILE_NAME", 1),
                ("NOESCAPE", 2),
                ("PERIOD", 4),
                ("LEADING_DIR", 8),
                ("CASEFOLD", 16),
            ];
            let fnm: Array =
                flags.iter().map(|(k, v)| (k.as_bytes().to_vec(), Cell::Val(Value::Num(f64::from(*v))))).collect();
            it.globals[i] = Cell::Arr(Rc::new(RefCell::new(fnm)));
        }
        for (name, val) in assigns {
            it.assign_cmdline(name, val).map_err(|e| match e {
                Flow::Fatal(m) => m,
                _ => String::new(),
            })?;
        }
        Ok(it)
    }

    fn assign_cmdline(&mut self, name: &[u8], val: &[u8]) -> Res<()> {
        if let Some(i) = self.prog.globals.iter().position(|g| g == name) {
            let v = Value::from_input(process_escapes(val));
            self.globals[i] = Cell::Val(v);
            self.assigned(i)?;
        }
        Ok(())
    }

    /// After global `i` changed: FS, FIELDWIDTHS and FPAT choose how
    /// fields split (the last one assigned wins, as in gawk).
    fn assigned(&mut self, i: usize) -> Res<()> {
        if !matches!(i, FS | FIELDWIDTHS | FPAT) {
            return Ok(());
        }
        if i == FIELDWIDTHS {
            self.widths = parse_widths(&self.global_text(FIELDWIDTHS)).map_err(Flow::Fatal)?;
        }
        self.split_by = i;
        if let Cell::Arr(p) = &self.globals[PROCINFO] {
            p.borrow_mut().insert(b"FS".to_vec(), Cell::from(Value::Str(self.prog.globals[i].clone())));
        }
        Ok(())
    }

    // --- variables ----------------------------------------------------------

    fn convfmt(&self) -> Vec<u8> {
        self.global_text(CONVFMT)
    }

    fn global_text(&self, i: usize) -> Vec<u8> {
        match &self.globals[i] {
            Cell::Val(v) => v.text(b"%.6g"),
            Cell::Arr(_) => Vec::new(),
        }
    }

    /// A global's text without a copy, when it is a string (RS and FS
    /// are read for every record).
    fn global_str(&self, i: usize) -> Option<&[u8]> {
        match &self.globals[i] {
            Cell::Val(Value::Str(s) | Value::StrNum(s)) => Some(s),
            _ => None,
        }
    }

    fn cell(&mut self, v: Var) -> &mut Cell {
        match v {
            Var::Global(i) => &mut self.globals[i],
            Var::Local(i) => {
                let f = self.frames.last_mut().expect("local outside a function");
                &mut f[i]
            }
        }
    }

    fn get_var(&mut self, v: Var) -> Res<Value> {
        if v == Var::Global(NF) {
            self.ensure_split();
            return Ok(Value::Num(self.fields.len() as f64));
        }
        match self.cell(v) {
            // Read before it was set: gawk's typeof says "unassigned" (and
            // of the caller's variable an unset argument came from).
            Cell::Val(x @ Value::Uninit) => {
                *x = Value::Unassigned;
                if let Var::Local(i) = v
                    && let Some(src) = self.sources.last().and_then(|s| s.get(i).copied().flatten())
                {
                    self.mark_read(src);
                }
                Ok(Value::Unassigned)
            }
            Cell::Val(x) => Ok(x.clone()),
            Cell::Arr(_) => fatal("attempt to use array in a scalar context"),
        }
    }

    /// The caller's variable `v` (one frame out) was read through a
    /// parameter.
    fn mark_read(&mut self, v: Var) {
        let cell = match v {
            Var::Global(i) => self.globals.get_mut(i),
            Var::Local(i) => {
                let n = self.frames.len();
                self.frames.get_mut(n.wrapping_sub(2)).and_then(|f| f.get_mut(i))
            }
        };
        if let Some(Cell::Val(x @ Value::Uninit)) = cell {
            *x = Value::Unassigned;
        }
    }

    fn set_var(&mut self, v: Var, val: Value) -> Res<()> {
        if v == Var::Global(NF) {
            let n = val.num();
            if n < 0.0 {
                return fatal("NF set to negative value");
            }
            self.set_nf(n as usize);
            return Ok(());
        }
        match self.cell(v) {
            c @ Cell::Val(_) => *c = Cell::Val(val),
            Cell::Arr(_) => return fatal("attempt to use array in a scalar context"),
        }
        match v {
            Var::Global(i) => self.assigned(i),
            Var::Local(_) => Ok(()),
        }
    }

    fn array(&mut self, v: Var) -> Res<Rc<RefCell<Array>>> {
        let c = self.cell(v);
        match c {
            Cell::Arr(a) => Ok(a.clone()),
            Cell::Val(Value::Uninit) => {
                let a = Rc::new(RefCell::new(Array::new()));
                *c = Cell::Arr(a.clone());
                Ok(a)
            }
            Cell::Val(_) => fatal("attempt to use scalar as an array"),
        }
    }

    /// The array at `path` below array variable `v`, subarrays made where
    /// there is nothing yet (gawk's arrays of arrays).
    fn array_at(&mut self, v: Var, path: &[Vec<Expr>]) -> Res<Rc<RefCell<Array>>> {
        let mut a = self.array(v)?;
        for subs in path {
            let k = self.subscript(subs)?;
            let next = {
                let mut b = a.borrow_mut();
                let e = b.entry(k).or_insert(Cell::Val(Value::Uninit));
                match e {
                    Cell::Arr(x) => x.clone(),
                    Cell::Val(Value::Uninit | Value::Unassigned) => {
                        let x = Rc::new(RefCell::new(Array::new()));
                        *e = Cell::Arr(x.clone());
                        x
                    }
                    Cell::Val(_) => return fatal("attempt to use a scalar value as array"),
                }
            };
            a = next;
        }
        Ok(a)
    }

    /// The element at `path` (the last list its subscript), if there.
    fn elem_cell(&mut self, v: Var, path: &[Vec<Expr>]) -> Res<Option<Cell>> {
        let Some((last, up)) = path.split_last() else { return Ok(Some(self.cell(v).clone())) };
        let a = self.array_at(v, up)?;
        let k = self.subscript(last)?;
        Ok(a.borrow().get(&k).cloned())
    }

    /// An array argument (split's, match's, asort's, a function's): a
    /// variable, or a subarray `a[i]`.
    fn array_arg(&mut self, e: Option<&Expr>, what: &str) -> Res<Rc<RefCell<Array>>> {
        match e {
            Some(Expr::Var(v)) => self.array(*v),
            Some(Expr::Index(v, path)) => self.array_at(*v, path),
            _ => fatal(alloc::format!("{what}: argument is not an array")),
        }
    }

    fn subscript(&mut self, subs: &[Expr]) -> Res<Vec<u8>> {
        let conv = self.convfmt();
        if subs.len() == 1 {
            let v = self.eval(&subs[0])?;
            return Ok(key_text(&v, &conv));
        }
        let sep = self.global_text(SUBSEP);
        let mut k = Vec::new();
        for (i, s) in subs.iter().enumerate() {
            if i > 0 {
                k.extend_from_slice(&sep);
            }
            let v = self.eval(s)?;
            k.extend_from_slice(&key_text(&v, &conv));
        }
        Ok(k)
    }

    // --- records and fields ---------------------------------------------------

    /// Whether IGNORECASE is set (gawk: regexes, string comparisons and
    /// index() then ignore case).
    fn icase(&self) -> bool {
        matches!(&self.globals[IGNORECASE], Cell::Val(v) if v.truthy())
    }

    fn compile_dyn(&mut self, p: &[u8]) -> Result<Rc<Regex>, String> {
        let icase = self.icase();
        let key = [&[icase as u8], p].concat();
        if let Some(r) = self.dyn_re.get(&key) {
            return Ok(r.clone());
        }
        let opts = Options {
            syntax: Syntax::Extended,
            escapes: true,
            icase,
            utf8: crate::util::utf8_locale(),
            ..Options::default()
        };
        let r = Rc::new(Regex::new(p, opts).map_err(|e| alloc::format!("{e}"))?);
        if self.dyn_re.len() > 500 {
            self.dyn_re.clear();
        }
        self.dyn_re.insert(key, r.clone());
        Ok(r)
    }

    fn re_cache(&mut self) -> impl FnMut(&[u8]) -> Option<Rc<Regex>> + '_ {
        |p: &[u8]| self.compile_dyn(p).ok()
    }

    fn dyn_regex(&mut self, p: &[u8]) -> Res<Rc<Regex>> {
        self.compile_dyn(p)
            .map_err(|e| Flow::Fatal(alloc::format!("invalid regex: {}: /{}/", e, String::from_utf8_lossy(p))))
    }

    /// The program's regex `i`, ignoring case when IGNORECASE says so.
    fn static_re(&mut self, i: usize) -> Rc<Regex> {
        if !self.icase() {
            return self.regexes[i].clone();
        }
        if let Some(r) = &self.regexes_icase[i] {
            return r.clone();
        }
        let opts = Options {
            syntax: Syntax::Extended,
            escapes: true,
            icase: true,
            utf8: crate::util::utf8_locale(),
            ..Options::default()
        };
        // It compiled without icase, so it compiles with it.
        let r = Regex::new(&self.prog.regexes[i], opts).map(Rc::new).unwrap_or_else(|_| self.regexes[i].clone());
        self.regexes_icase[i] = Some(r.clone());
        r
    }

    fn set_record(&mut self, r: Vec<u8>) {
        self.record = r;
        self.split_done = false;
        // The last record's FS, if it is still FS.
        if self.split_by != FIELDWIDTHS
            && self.split_by != FPAT
            && let Splitter::Fs(old) = &self.record_split
            && self.global_str(FS) == Some(old.as_slice())
        {
            return;
        }
        self.record_split = match self.split_by {
            FIELDWIDTHS => Splitter::Widths(self.widths.clone()),
            FPAT => Splitter::Pat(self.global_text(FPAT)),
            _ => Splitter::Fs(self.global_text(FS)),
        };
    }

    fn ensure_split(&mut self) {
        if self.split_done {
            return;
        }
        self.split_done = true;
        let paragraph = self.global_str(RS).map_or_else(|| self.global_text(RS).is_empty(), <[u8]>::is_empty);
        let record = core::mem::take(&mut self.record);
        let fields = match core::mem::replace(&mut self.record_split, Splitter::Fs(Vec::new())) {
            Splitter::Fs(fs) => {
                let mut fields = core::mem::take(&mut self.fields);
                {
                    let mut re = self.re_cache();
                    split_into(&record, &fs, paragraph, &mut re, &mut fields);
                }
                self.record_split = Splitter::Fs(fs);
                fields
            }
            Splitter::Widths(w) => {
                let fields = split_widths(&record, &w);
                self.record_split = Splitter::Widths(w);
                fields
            }
            Splitter::Pat(p) => {
                let fields = match self.compile_dyn(&p) {
                    Ok(re) => pattern_split(&record, &re).0,
                    Err(_) => alloc::vec![record.clone()],
                };
                self.record_split = Splitter::Pat(p);
                fields
            }
        };
        self.record = record;
        self.fields = fields;
    }

    fn rebuild(&mut self) {
        let ofs = self.global_text(OFS);
        self.record = self.fields.join(ofs.as_slice());
    }

    fn get_field(&mut self, n: f64) -> Res<Value> {
        if n < 0.0 {
            return fatal(alloc::format!("attempt to access field {}", n as i64));
        }
        let n = n as usize;
        if n == 0 {
            return Ok(Value::from_input(self.record.clone()));
        }
        self.ensure_split();
        Ok(self.fields.get(n - 1).map_or(Value::Uninit, |f| Value::from_input(f.clone())))
    }

    fn set_field(&mut self, n: f64, text: Vec<u8>) -> Res<()> {
        if n < 0.0 {
            return fatal(alloc::format!("attempt to access field {}", n as i64));
        }
        let n = n as usize;
        if n == 0 {
            self.set_record(text);
            return Ok(());
        }
        self.ensure_split();
        if self.fields.len() < n {
            self.fields.resize(n, Vec::new());
        }
        self.fields[n - 1] = text;
        self.rebuild();
        Ok(())
    }

    fn set_nf(&mut self, n: usize) {
        self.ensure_split();
        self.fields.resize(n, Vec::new());
        self.rebuild();
    }

    // --- input ------------------------------------------------------------------

    fn flush(&mut self) {
        if !self.out.is_empty() {
            io::out(&self.out);
            self.out.clear();
        }
        io::flush_stdout();
    }

    /// Open the next ARGV file; false when there are no more.
    /// Open the next input file (running BEGINFILE); false at the end.
    fn open_next(&mut self) -> Res<bool> {
        let prog = self.prog;
        loop {
            let argc = match &self.globals[ARGC] {
                Cell::Val(v) => v.num() as usize,
                _ => 0,
            };
            let (arg, fd) = if self.argi >= argc {
                if self.used_file {
                    return Ok(false);
                }
                // No files: standard input, which gawk names `-`.
                self.used_file = true;
                (b"-".to_vec(), Ok(0))
            } else {
                let key = alloc::format!("{}", self.argi).into_bytes();
                self.argi += 1;
                let arg = match &self.globals[ARGV] {
                    Cell::Arr(a) => a.borrow().get(&key).map(|v| v.text(b"%.6g")),
                    _ => None,
                };
                let Some(arg) = arg else { continue };
                if arg.is_empty() {
                    continue;
                }
                if let Some(eq) = arg.iter().position(|&c| c == b'=')
                    && crate::util::is_name(&arg[..eq])
                {
                    let (n, v) = (arg[..eq].to_vec(), arg[eq + 1..].to_vec());
                    self.assign_cmdline(&n, &v)?;
                    continue;
                }
                self.used_file = true;
                let fd = if arg == b"-" || arg == b"/dev/stdin" {
                    Ok(0)
                } else {
                    fs::open(&arg, fs::O_RDONLY | fs::O_CLOEXEC, 0)
                };
                (arg, fd)
            };
            let fd = match fd {
                Ok(fd) => fd,
                Err(e) if prog.beginfile.is_empty() => {
                    self.flush();
                    crate::util::error(alloc::format!(
                        "warning: command line argument `{}': {e}",
                        String::from_utf8_lossy(&arg)
                    ));
                    self.exit_code = 2;
                    continue;
                }
                Err(e) => {
                    // BEGINFILE sees ERRNO and may skip the file with
                    // nextfile; otherwise it is fatal (gawk manual,
                    // "The BEGINFILE and ENDFILE Special Patterns").
                    let message = alloc::format!("{e}");
                    self.globals[ERRNO] = Cell::Val(Value::Str(message.clone().into_bytes()));
                    self.globals[FILENAME] = Cell::Val(Value::Str(arg.clone()));
                    self.globals[FNR] = Cell::Val(Value::Num(0.0));
                    match self.exec_block(&prog.beginfile) {
                        Err(Flow::NextFile) => continue,
                        Err(e) => return Err(e),
                        Ok(()) => {
                            return fatal(alloc::format!(
                                "cannot open file `{}' for reading: {message}",
                                String::from_utf8_lossy(&arg)
                            ));
                        }
                    }
                }
            };
            // readdir (`@load "readdir"`): a directory reads as a record
            // per entry, `ino/name/type`, as gawk's extension gives them.
            let fd = if prog.loaded.contains(&"readdir") && fd > 0 && fs::fstat(fd).is_ok_and(|s| s.is_dir()) {
                let _ = io::close(fd);
                listing(&arg).unwrap_or(-1)
            } else {
                fd
            };
            self.globals[FILENAME] = Cell::Val(Value::Str(arg));
            self.globals[FNR] = Cell::Val(Value::Num(0.0));
            self.main = Some(Records::new(fd));
            if !prog.beginfile.is_empty() {
                self.globals[ERRNO] = Cell::Val(Value::Str(Vec::new()));
                match self.exec_block(&prog.beginfile) {
                    Ok(()) => {}
                    Err(Flow::NextFile) => {
                        self.end_file()?;
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            return Ok(true);
        }
    }

    fn close_main(&mut self) {
        if let Some(m) = self.main.take()
            && m.fd > 0
        {
            let _ = io::close(m.fd);
        }
    }

    /// The end of an input file (or nextfile): ENDFILE, then close it.
    fn end_file(&mut self) -> Res<()> {
        let prog = self.prog;
        let r = self.exec_block(&prog.endfile);
        self.close_main();
        match r {
            Ok(()) | Err(Flow::NextFile) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// The next main-input record (sets NR and FNR).
    fn next_main(&mut self) -> Res<Option<Vec<u8>>> {
        loop {
            if self.main.is_none() && !self.open_next()? {
                return Ok(None);
            }
            // RS is almost always one byte: copied, not allocated.
            let one: [u8; 1];
            let owned: Vec<u8>;
            let rs: &[u8] = match self.global_str(RS) {
                Some(&[b]) => {
                    one = [b];
                    &one
                }
                _ => {
                    owned = self.global_text(RS);
                    &owned
                }
            };
            let Some(mut main) = self.main.take() else { return Ok(None) };
            let r = {
                let mut re = self.re_cache();
                main.next(rs, &mut re)
            };
            self.main = Some(main);
            match r {
                Some((rec, rt)) => {
                    let inc = |c: &mut Cell| {
                        let n = match c {
                            Cell::Val(v) => v.num(),
                            _ => 0.0,
                        };
                        *c = Cell::Val(Value::Num(n + 1.0));
                    };
                    inc(&mut self.globals[NR]);
                    inc(&mut self.globals[FNR]);
                    self.globals[RT] = Cell::Val(Value::Str(rt));
                    return Ok(Some(rec));
                }
                None => self.end_file()?,
            }
        }
    }

    fn spawn(&mut self, cmd: &[u8], read: bool) -> Res<(i32, i32)> {
        self.flush();
        let (r, w) = process::pipe(fs::O_CLOEXEC).map_err(|e| Flow::Fatal(alloc::format!("pipe: {e}")))?;
        match process::fork() {
            Ok(0) => {
                if read {
                    let _ = process::dup2(w, 1);
                } else {
                    let _ = process::dup2(r, 0);
                }
                let argv = alloc::vec![b"sh".to_vec(), b"-c".to_vec(), cmd.to_vec()];
                let e = process::execve(b"/bin/sh", &argv, slate_rt::env::vars());
                crate::util::error(alloc::format!("/bin/sh: {e}"));
                process::exit_now(127);
            }
            Ok(pid) => {
                if read {
                    let _ = io::close(w);
                    Ok((r, pid))
                } else {
                    let _ = io::close(r);
                    Ok((w, pid))
                }
            }
            Err(e) => fatal(alloc::format!("fork: {e}")),
        }
    }

    fn getline(&mut self, src: &GetSrc, lv: &Option<Box<Expr>>) -> Res<Value> {
        let rec = match src {
            GetSrc::Main => match self.next_main()? {
                Some(r) => r,
                None => return Ok(Value::Num(0.0)),
            },
            GetSrc::File(f) | GetSrc::Cmd(f) => {
                let is_cmd = matches!(src, GetSrc::Cmd(_));
                let name = {
                    let v = self.eval(f)?;
                    v.text(&self.convfmt())
                };
                let idx = match self.inputs.iter().position(|(n, _, _)| *n == name) {
                    Some(i) => i,
                    None => {
                        let (fd, pid) = if is_cmd {
                            self.spawn(&name, true)?
                        } else if name == b"-" || name == b"/dev/stdin" {
                            (0, 0)
                        } else {
                            match fs::open(&name, fs::O_RDONLY | fs::O_CLOEXEC, 0) {
                                Ok(fd) => (fd, 0),
                                Err(e) => {
                                    self.globals[ERRNO] = Cell::Val(Value::Str(alloc::format!("{e}").into_bytes()));
                                    return Ok(Value::Num(-1.0));
                                }
                            }
                        };
                        self.inputs.push((name.clone(), Records::new(fd), pid));
                        self.inputs.len() - 1
                    }
                };
                let rs = self.global_text(RS);
                let mut recs = core::mem::replace(&mut self.inputs[idx].1, Records::new(-1));
                let r = {
                    let mut re = self.re_cache();
                    recs.next(&rs, &mut re)
                };
                self.inputs[idx].1 = recs;
                // A file or a command leaves NR and FNR alone (gawk's
                // table of getline's forms: `cmd | getline` sets $0, NF and
                // RT, `cmd | getline var` var and RT).
                match r {
                    Some((rec, rt)) => {
                        self.globals[RT] = Cell::Val(Value::Str(rt));
                        rec
                    }
                    None => return Ok(Value::Num(0.0)),
                }
            }
        };
        match lv {
            Some(l) => self.assign(l, Value::from_input(rec))?,
            None => self.set_record(rec),
        }
        Ok(Value::Num(1.0))
    }

    // --- output -------------------------------------------------------------------

    fn write_to(&mut self, redir: &Option<(Redir, Expr)>, data: &[u8]) -> Res<()> {
        let Some((kind, target)) = redir else {
            self.out.extend_from_slice(data);
            if self.out.len() > 32 * 1024 {
                self.flush();
            }
            return Ok(());
        };
        let name = {
            let v = self.eval(target)?;
            v.text(&self.convfmt())
        };
        if *kind != Redir::Pipe {
            match name.as_slice() {
                b"/dev/stdout" | b"-" => {
                    self.out.extend_from_slice(data);
                    return Ok(());
                }
                // Unbuffered, while stdout stays buffered (as in gawk).
                b"/dev/stderr" => {
                    io::err(data);
                    return Ok(());
                }
                _ => {}
            }
        }
        let fd = match self.outputs.iter().find(|(n, _)| *n == name) {
            Some((_, Output::File(fd) | Output::Pipe(fd, _))) => *fd,
            None => {
                let out = match kind {
                    Redir::Pipe => {
                        let (fd, pid) = self.spawn(&name, false)?;
                        Output::Pipe(fd, pid)
                    }
                    _ => {
                        let flags = fs::O_WRONLY
                            | fs::O_CREAT
                            | fs::O_CLOEXEC
                            | if *kind == Redir::Append { fs::O_APPEND } else { fs::O_TRUNC };
                        match fs::open(&name, flags, 0o666) {
                            Ok(fd) => Output::File(fd),
                            Err(e) => {
                                return fatal(alloc::format!(
                                    "can't redirect to `{}': {e}",
                                    String::from_utf8_lossy(&name)
                                ));
                            }
                        }
                    }
                };
                let fd = match out {
                    Output::File(fd) | Output::Pipe(fd, _) => fd,
                };
                self.outputs.push((name, out));
                fd
            }
        };
        self.flush();
        let _ = io::write_all(fd, data);
        Ok(())
    }

    fn close(&mut self, name: &[u8]) -> i32 {
        let mut status = -1;
        if let Some(i) = self.outputs.iter().position(|(n, _)| n == name) {
            self.flush();
            let (_, o) = self.outputs.remove(i);
            status = match o {
                Output::File(fd) => {
                    let _ = io::close(fd);
                    0
                }
                Output::Pipe(fd, pid) => {
                    let _ = io::close(fd);
                    process::wait(pid, 0).map_or(-1, |(_, s)| process::exit_code(s))
                }
            };
        }
        if let Some(i) = self.inputs.iter().position(|(n, _, _)| n == name) {
            let (_, r, pid) = self.inputs.remove(i);
            if r.fd > 0 {
                let _ = io::close(r.fd);
            }
            status = if pid > 0 { process::wait(pid, 0).map_or(-1, |(_, s)| process::exit_code(s)) } else { 0 };
        }
        status
    }

    pub fn close_all(&mut self) {
        self.flush();
        let names: Vec<Vec<u8>> = self.outputs.iter().map(|(n, _)| n.clone()).collect();
        for n in names {
            self.close(&n);
        }
        let names: Vec<Vec<u8>> = self.inputs.iter().map(|(n, _, _)| n.clone()).collect();
        for n in names {
            self.close(&n);
        }
    }

    // --- expressions ----------------------------------------------------------------

    fn assign(&mut self, lv: &Expr, v: Value) -> Res<()> {
        match lv {
            Expr::Var(var) => self.set_var(*var, v),
            Expr::Index(var, path) => {
                let (last, up) = path.split_last().expect("a subscript");
                let a = self.array_at(*var, up)?;
                let k = self.subscript(last)?;
                let mut a = a.borrow_mut();
                match a.get_mut(&k) {
                    Some(Cell::Arr(_)) => fatal("attempt to use array in a scalar context"),
                    Some(Cell::Val(x)) => {
                        *x = v;
                        Ok(())
                    }
                    None => {
                        a.insert(k, Cell::Val(v));
                        Ok(())
                    }
                }
            }
            Expr::Field(e) => {
                let n = self.eval(e)?.num();
                let t = v.text(&self.convfmt());
                self.set_field(n, t)
            }
            Expr::Group(g) if g.len() == 1 => self.assign(&g[0], v),
            _ => fatal("assignment to a non-variable"),
        }
    }

    fn regex_of(&mut self, e: &Expr) -> Res<Rc<Regex>> {
        if let Expr::Regex(i) = e {
            return Ok(self.static_re(*i));
        }
        let v = self.eval(e)?;
        let p = v.text(&self.convfmt());
        self.dyn_regex(&p)
    }

    fn compare(&self, a: &Value, b: &Value) -> core::cmp::Ordering {
        if a.numeric()
            && b.numeric()
            && let (Some(x), Some(y)) = (self.big_of(a), self.big_of(b))
        {
            return x.cmp(&y);
        }
        if a.numeric() && b.numeric() {
            let (x, y) = (a.num(), b.num());
            return x.partial_cmp(&y).unwrap_or(core::cmp::Ordering::Equal);
        }
        let conv = self.convfmt();
        self.text_cmp(&a.text(&conv), &b.text(&conv))
    }

    fn text_cmp(&self, a: &[u8], b: &[u8]) -> core::cmp::Ordering {
        if self.icase() {
            let lower = |s: &[u8]| s.iter().map(u8::to_ascii_lowercase).collect::<Vec<u8>>();
            return lower(a).cmp(&lower(b));
        }
        a.cmp(b)
    }

    pub fn eval(&mut self, e: &Expr) -> Res<Value> {
        Ok(match e {
            Expr::Num(n) => Value::Num(*n),
            Expr::Str(s) => Value::Str(s.clone()),
            Expr::Regex(i) => {
                let r = self.static_re(*i);
                Value::Num(r.is_match(&self.record) as i32 as f64)
            }
            Expr::Var(v) => self.get_var(*v)?,
            Expr::Index(v, path) => {
                let (last, up) = path.split_last().expect("a subscript");
                let a = if up.is_empty() { self.array(*v)? } else { self.array_at(*v, up)? };
                let k = self.subscript(last)?;
                let mut a = a.borrow_mut();
                match a.entry(k).or_insert(Cell::Val(Value::Uninit)) {
                    Cell::Val(x) => x.clone(),
                    Cell::Arr(_) => return fatal("attempt to use array in a scalar context"),
                }
            }
            Expr::TypedRegex(p) => Value::Regex(p.clone()),
            Expr::BigNum(t) => match Big::parse(t) {
                Some(b) if self.bignum => Value::Big(b),
                _ => Value::Num(value::str_to_num(t)),
            },
            Expr::Field(n) => {
                let n = self.eval(n)?.num();
                self.get_field(n)?
            }
            Expr::In(subs, v, path) => {
                let k = self.subscript(subs)?;
                let a = self.array_at(*v, path)?;
                Value::Num(a.borrow().contains_key(&k) as i32 as f64)
            }
            Expr::Assign(op, lv, rhs) => {
                let r = self.eval(rhs)?;
                let v = match op {
                    None => r,
                    Some(op) => {
                        let l = self.eval(lv)?;
                        self.arith_values(*op, &l, &r)?
                    }
                };
                self.assign(lv, v.clone())?;
                v
            }
            Expr::Cond(c, a, b) => {
                if self.eval(c)?.truthy() {
                    self.eval(a)?
                } else {
                    self.eval(b)?
                }
            }
            Expr::And(a, b) => Value::Num((self.eval(a)?.truthy() && self.eval(b)?.truthy()) as i32 as f64),
            Expr::Or(a, b) => Value::Num((self.eval(a)?.truthy() || self.eval(b)?.truthy()) as i32 as f64),
            Expr::Not(a) => Value::Num(!self.eval(a)?.truthy() as i32 as f64),
            Expr::Bin(op, a, b) => {
                let x = self.eval(a)?;
                let y = self.eval(b)?;
                self.arith_values(*op, &x, &y)?
            }
            Expr::Cmp(op, a, b) => {
                let x = self.eval(a)?;
                let y = self.eval(b)?;
                let o = self.compare(&x, &y);
                use core::cmp::Ordering::*;
                let r = match op {
                    CmpOp::Lt => o == Less,
                    CmpOp::Le => o != Greater,
                    CmpOp::Eq => o == Equal,
                    CmpOp::Ne => o != Equal,
                    CmpOp::Gt => o == Greater,
                    CmpOp::Ge => o != Less,
                };
                Value::Num(r as i32 as f64)
            }
            Expr::Neg(a) => {
                let v = self.eval(a)?;
                match self.big_of(&v) {
                    Some(b) => Value::Big(b.neg()),
                    None => Value::Num(-v.num()),
                }
            }
            Expr::Plus(a) => {
                let v = self.eval(a)?;
                match self.big_of(&v) {
                    Some(b) => Value::Big(b),
                    None => Value::Num(v.num()),
                }
            }
            Expr::Concat(a, b) => {
                let conv = self.convfmt();
                let mut x = self.eval(a)?.text(&conv);
                let y = self.eval(b)?.text(&conv);
                x.extend_from_slice(&y);
                Value::Str(x)
            }
            Expr::Match(neg, s, r) => {
                let t = {
                    let v = self.eval(s)?;
                    v.text(&self.convfmt())
                };
                let re = self.regex_of(r)?;
                Value::Num((re.is_match(&t) != *neg) as i32 as f64)
            }
            Expr::IncDec { pre, inc, lv } => {
                let v = self.eval(lv)?;
                let (old, new) = match self.big_of(&v) {
                    Some(b) => {
                        let n = b.add(&Big::from_i64(if *inc { 1 } else { -1 }));
                        (Value::Big(b), Value::Big(n))
                    }
                    None => {
                        let old = v.num();
                        (Value::Num(old), Value::Num(if *inc { old + 1.0 } else { old - 1.0 }))
                    }
                };
                self.assign(lv, new.clone())?;
                if *pre { new } else { old }
            }
            Expr::Builtin(name, args) => self.builtin(name, args)?,
            Expr::Call(f, args) => self.call(*f, args)?,
            Expr::Getline { src, lv } => self.getline(src, lv)?,
            Expr::Group(g) => match g.as_slice() {
                // A parenthesized lvalue is a plain value.
                [one] => self.eval(one)?,
                _ => {
                    // (a, b) outside print: concatenation with SUBSEP (gawk errors).
                    let sep = self.global_text(SUBSEP);
                    let conv = self.convfmt();
                    let mut out = Vec::new();
                    for (i, x) in g.iter().enumerate() {
                        if i > 0 {
                            out.extend_from_slice(&sep);
                        }
                        let v = self.eval(x)?;
                        out.extend_from_slice(&v.text(&conv));
                    }
                    Value::Str(out)
                }
            },
        })
    }

    /// `v` as an exact integer, with `-M`: a Big, an integral number, or
    /// text that is an integer (or nothing).
    fn big_of(&self, v: &Value) -> Option<Big> {
        if !self.bignum {
            return None;
        }
        match v {
            Value::Big(b) => Some(b.clone()),
            Value::Num(n) => Big::from_f64(*n),
            Value::Uninit | Value::Unassigned => Some(Big::default()),
            Value::StrNum(s) | Value::Str(s) => Big::parse(s),
            Value::Regex(_) => None,
        }
    }

    /// `x op y`: exact with `-M` when both are integers (a quotient that
    /// isn't whole, and a negative power, are doubles), else doubles.
    fn arith_values(&self, op: BinOp, x: &Value, y: &Value) -> Res<Value> {
        if let (Some(a), Some(b)) = (self.big_of(x), self.big_of(y)) {
            return Ok(match op {
                BinOp::Add => Value::Big(a.add(&b)),
                BinOp::Sub => Value::Big(a.sub(&b)),
                BinOp::Mul => Value::Big(a.mul(&b)),
                BinOp::Div => match a.divmod(&b) {
                    None => return fatal("division by zero attempted"),
                    Some((q, r)) if r.is_zero() => Value::Big(q),
                    Some(_) => Value::Num(a.to_f64() / b.to_f64()),
                },
                BinOp::Mod => match a.divmod(&b) {
                    None => return fatal("division by zero attempted in `%'"),
                    Some((_, r)) => Value::Big(r),
                },
                BinOp::Pow => match b.to_f64() {
                    e if (0.0..=1e6).contains(&e) => Value::Big(a.pow(e as u64)),
                    e => Value::Num(math::pow(a.to_f64(), e)),
                },
            });
        }
        Ok(Value::Num(self.arith(op, x.num(), y.num())?))
    }

    fn arith(&self, op: BinOp, x: f64, y: f64) -> Res<f64> {
        Ok(match op {
            BinOp::Add => x + y,
            BinOp::Sub => x - y,
            BinOp::Mul => x * y,
            BinOp::Div => {
                if y == 0.0 {
                    return fatal("division by zero attempted");
                }
                x / y
            }
            BinOp::Mod => {
                if y == 0.0 {
                    return fatal("division by zero attempted in `%'");
                }
                math::fmod(x, y)
            }
            BinOp::Pow => math::pow(x, y),
        })
    }

    fn call(&mut self, fi: usize, args: &[Expr]) -> Res<Value> {
        let f = &self.prog.funcs[fi];
        if args.len() > f.params.len() {
            return fatal(alloc::format!(
                "function `{}' called with more arguments than declared",
                String::from_utf8_lossy(&f.name)
            ));
        }
        let mut frame = Vec::with_capacity(f.params.len());
        let mut sources: Vec<Option<Var>> = Vec::new();
        for (i, &is_array) in f.arrays.iter().enumerate() {
            let cell = match args.get(i) {
                Some(Expr::Var(v)) if is_array => Cell::Arr(self.array(*v)?),
                Some(Expr::Var(v)) if matches!(self.cell(*v), Cell::Arr(_)) => self.cell(*v).clone(),
                // A subarray passes as an array.
                Some(Expr::Index(v, path)) if is_array => Cell::Arr(self.array_at(*v, path)?),
                Some(e @ Expr::Index(v, path)) => match self.elem_cell(*v, path)? {
                    Some(c @ Cell::Arr(_)) => c,
                    _ => Cell::Val(self.eval(e)?),
                },
                // Passing a variable doesn't read it (gawk's typeof stays
                // "untyped" until the function reads the parameter).
                Some(Expr::Var(v)) if *v != Var::Global(NF) => {
                    if matches!(self.cell(*v), Cell::Val(Value::Uninit)) {
                        sources.resize(i + 1, None);
                        sources[i] = Some(*v);
                    }
                    self.cell(*v).clone()
                }
                Some(a) => Cell::Val(self.eval(a)?),
                None if is_array => Cell::Arr(Rc::new(RefCell::new(Array::new()))),
                None => Cell::Val(Value::Uninit),
            };
            frame.push(cell);
        }
        self.run_frame_from(frame, sources, &f.body)
    }

    /// Call function `fi` with values (a sort's comparison function).
    fn call_values(&mut self, fi: usize, vals: Vec<Value>) -> Res<Value> {
        let f = &self.prog.funcs[fi];
        let mut vals = vals.into_iter();
        let frame = f
            .arrays
            .iter()
            .map(|&is_array| match (is_array, vals.next()) {
                (true, _) => Cell::Arr(Rc::new(RefCell::new(Array::new()))),
                (false, v) => Cell::Val(v.unwrap_or(Value::Uninit)),
            })
            .collect();
        self.run_frame(frame, &f.body)
    }

    fn run_frame(&mut self, frame: Vec<Cell>, body: &'p [Stmt]) -> Res<Value> {
        if self.depth > 2000 {
            return fatal("function call nesting too deep");
        }
        self.run_frame_from(frame, Vec::new(), body)
    }

    fn run_frame_from(&mut self, frame: Vec<Cell>, sources: Vec<Option<Var>>, body: &'p [Stmt]) -> Res<Value> {
        if self.depth > 2000 {
            return fatal("function call nesting too deep");
        }
        self.frames.push(frame);
        self.sources.push(sources);
        self.depth += 1;
        let r = self.exec_block(body);
        self.depth -= 1;
        self.frames.pop();
        self.sources.pop();
        match r {
            Ok(()) => Ok(Value::Uninit),
            Err(Flow::Return(v)) => Ok(v),
            Err(e) => Err(e),
        }
    }

    /// Whether `case c` takes value `v`: a regex matches its text, a
    /// number equals a numeric value, otherwise the texts are compared
    /// (as gawk was seen to: `"10"` matches `case 10`, `"1.0"` not `case 1`).
    fn case_matches(&mut self, c: &Case, v: &Value) -> bool {
        let conv = self.convfmt();
        match c {
            Case::Default => false,
            Case::Regex(i) => self.static_re(*i).is_match(&v.text(&conv)),
            Case::Num(n) if matches!(v, Value::Num(_) | Value::StrNum(_)) => v.num() == *n,
            Case::Num(n) => v.text(&conv) == num_to_str(*n, &conv),
            Case::Str(t) => v.text(&conv) == *t,
        }
    }

    // --- array order ---------------------------------------------------------------

    /// The order `for (k in a)` visits keys: PROCINFO["sorted_in"]'s, or
    /// else gawk's usual order for arrays whose keys start as integers:
    /// other keys first, then integers 0 to 2^31-1 ascending.
    fn traversal(&mut self, a: &Rc<RefCell<Array>>) -> Res<Vec<Vec<u8>>> {
        let how = match &self.globals[PROCINFO] {
            Cell::Arr(p) => p.borrow().get(b"sorted_in".as_slice()).map(|v| v.text(b"%.6g")),
            Cell::Val(_) => None,
        };
        let items: Vec<(Vec<u8>, Value)> = a.borrow().iter().map(|(k, v)| (k.clone(), v.val())).collect();
        match how {
            Some(how) if !how.is_empty() && how != b"@unsorted" => {
                Ok(self.sorted(items, &how)?.into_iter().map(|(k, _)| k).collect())
            }
            _ => {
                let (mut ints, mut keys): (Vec<_>, Vec<_>) =
                    items.into_iter().map(|(k, _)| k).partition(|k| integer_key(k).is_some());
                ints.sort_by_key(|k| integer_key(k));
                keys.extend(ints);
                Ok(keys)
            }
        }
    }

    /// `items` in order `how` (gawk manual, "Controlling Array
    /// Traversal"): `@ind_str`, `@ind_num`, `@val_type`, `@val_str`,
    /// `@val_num` with `_asc` or `_desc`, or a function's name. Ties go by
    /// index (`@val_num` first by the values as strings), and `_desc`
    /// reverses the whole order, as gawk was seen to.
    fn sorted(&mut self, mut items: Vec<Item>, how: &[u8]) -> Res<Vec<Item>> {
        use core::cmp::Ordering;
        let conv = self.convfmt();
        if how.first() != Some(&b'@') {
            let name = how;
            let Some(fi) = self.prog.funcs.iter().position(|f| f.name == name && f.defined) else {
                return fatal(alloc::format!("sort comparison function `{}' is not defined", lossy_str(name)));
            };
            let mut failed = None;
            // Merge sort: stable, and a failing call stops the comparing.
            let mut cmp = |a: &Item, b: &Item| -> Ordering {
                if failed.is_some() {
                    return Ordering::Equal;
                }
                let vals = alloc::vec![Value::Str(a.0.clone()), a.1.clone(), Value::Str(b.0.clone()), b.1.clone()];
                match self.call_values(fi, vals) {
                    Ok(v) => v.num().partial_cmp(&0.0).unwrap_or(Ordering::Equal),
                    Err(e) => {
                        failed = Some(e);
                        Ordering::Equal
                    }
                }
            };
            items.sort_by(&mut cmp);
            return match failed {
                Some(e) => Err(e),
                None => Ok(items),
            };
        }
        let (kind, desc) = match how {
            _ if how.ends_with(b"_asc") => (&how[1..how.len() - 4], false),
            _ if how.ends_with(b"_desc") => (&how[1..how.len() - 5], true),
            _ => return fatal(alloc::format!("`{}' is not a valid sorted_in order", lossy_str(how))),
        };
        let num = |a: &Value, b: &Value| a.num().partial_cmp(&b.num()).unwrap_or(Ordering::Equal);
        let order: &dyn Fn(&Item, &Item) -> Ordering = match kind {
            b"ind_str" => &|a, b| a.0.cmp(&b.0),
            b"ind_num" => &|a, b| {
                let n = |k: &[u8]| value::str_to_num(k);
                n(&a.0).partial_cmp(&n(&b.0)).unwrap_or(Ordering::Equal).then_with(|| a.0.cmp(&b.0))
            },
            b"val_type" => &|a, b| match (a.1.numeric(), b.1.numeric()) {
                (true, true) => num(&a.1, &b.1).then_with(|| a.0.cmp(&b.0)),
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                (false, false) => self.text_cmp(&a.1.text(&conv), &b.1.text(&conv)).then_with(|| a.0.cmp(&b.0)),
            },
            b"val_str" => &|a, b| self.text_cmp(&a.1.text(&conv), &b.1.text(&conv)).then_with(|| a.0.cmp(&b.0)),
            b"val_num" => &|a, b| {
                num(&a.1, &b.1)
                    .then_with(|| self.text_cmp(&a.1.text(&conv), &b.1.text(&conv)))
                    .then_with(|| a.0.cmp(&b.0))
            },
            _ => return fatal(alloc::format!("`{}' is not a valid sorted_in order", lossy_str(how))),
        };
        items.sort_by(|a, b| if desc { order(b, a) } else { order(a, b) });
        Ok(items)
    }

    /// split()'s fourth argument (gawk): the separators, by number; with
    /// FS " " the leading and trailing white space are 0 and n.
    fn separators(&mut self, s: &[u8], fs: &[u8], regex: bool) -> Res<Vec<(usize, Vec<u8>)>> {
        let mut out = Vec::new();
        if s.is_empty() {
            return Ok(out);
        }
        if fs == b" " && !regex {
            let ws = |c: &u8| matches!(c, b' ' | b'\t' | b'\n');
            let mut runs = Vec::new();
            let mut i = 0;
            while i < s.len() {
                let start = i;
                while i < s.len() && ws(&s[i]) {
                    i += 1;
                }
                if i > start {
                    runs.push((start, i));
                }
                while i < s.len() && !ws(&s[i]) {
                    i += 1;
                }
            }
            let mut n = 0;
            for (a, b) in runs {
                if a == 0 {
                    out.push((0, s[a..b].to_vec()));
                    continue;
                }
                n += 1;
                out.push((n, s[a..b].to_vec()));
            }
            return Ok(out);
        }
        if fs.is_empty() {
            return Ok((1..s.len()).map(|i| (i, Vec::new())).collect());
        }
        if fs.len() == 1 && fs[0] != b'\\' && !regex {
            let n = s.iter().filter(|&&c| c == fs[0]).count();
            return Ok((1..=n).map(|i| (i, fs.to_vec())).collect());
        }
        let re = self.dyn_regex(fs)?;
        let mut pos = 0;
        while pos <= s.len() {
            match re.find_at(s, pos).and_then(|c| c[0]) {
                Some((a, b)) if b > a => {
                    out.push((out.len() + 1, s[a..b].to_vec()));
                    pos = b;
                }
                Some((a, _)) if a < s.len() => pos = a + 1,
                _ => break,
            }
        }
        Ok(out)
    }

    /// A bit function's argument: a whole number from 0 up.
    fn bits_arg(&mut self, name: &str, args: &[Expr], i: usize) -> Res<u64> {
        let n = self.arg_num(args, i)?;
        if n < 0.0 {
            return fatal(alloc::format!("{name}: argument {} negative value {} is not allowed", i + 1, n));
        }
        Ok(math::trunc(n) as u64)
    }

    /// asort() and asorti() (gawk): sort the source's values (or indices)
    /// into `dest[1..n]`, or into the source itself.
    fn asort(&mut self, args: &[Expr], indices: bool) -> Res<Value> {
        let name = if indices { "asorti" } else { "asort" };
        if !matches!(args.first(), Some(Expr::Var(_) | Expr::Index(..))) {
            return fatal(alloc::format!("{name}: first argument is not an array"));
        }
        if args.get(1).is_some_and(|d| !matches!(d, Expr::Var(_) | Expr::Index(..))) {
            return fatal(alloc::format!("{name}: second argument is not an array"));
        }
        let how = match args.get(2) {
            Some(e) => {
                let v = self.eval(e)?;
                v.text(&self.convfmt())
            }
            None if indices => b"@ind_str_asc".to_vec(),
            None => b"@val_type_asc".to_vec(),
        };
        let a = self.array_arg(args.first(), name)?;
        let items: Vec<(Vec<u8>, Value)> = a.borrow().iter().map(|(k, v)| (k.clone(), v.val())).collect();
        let items = self.sorted(items, &how)?;
        let out = if args.get(1).is_some() { self.array_arg(args.get(1), name)? } else { a };
        let mut out = out.borrow_mut();
        out.clear();
        let n = items.len();
        for (i, (k, v)) in items.into_iter().enumerate() {
            out.insert(alloc::format!("{}", i + 1).into_bytes(), Cell::from(if indices { Value::Str(k) } else { v }));
        }
        Ok(Value::Num(n as f64))
    }

    // --- built-in functions ------------------------------------------------------

    /// Characters in `s` (bytes outside a UTF-8 locale).
    fn chars(&self, s: &[u8]) -> usize {
        if self.utf8 { s.iter().filter(|&&c| c & 0xC0 != 0x80).count() } else { s.len() }
    }

    /// The byte where character `n` (0-based) of `s` starts (its length
    /// past the end).
    fn byte_of(&self, s: &[u8], n: usize) -> usize {
        if !self.utf8 {
            return n.min(s.len());
        }
        s.iter().enumerate().filter(|(_, c)| **c & 0xC0 != 0x80).nth(n).map_or(s.len(), |(i, _)| i)
    }

    fn arg_num(&mut self, args: &[Expr], i: usize) -> Res<f64> {
        match args.get(i) {
            Some(e) => Ok(self.eval(e)?.num()),
            None => Ok(0.0),
        }
    }

    fn arg_text(&mut self, args: &[Expr], i: usize) -> Res<Vec<u8>> {
        match args.get(i) {
            Some(e) => {
                let v = self.eval(e)?;
                Ok(v.text(&self.convfmt()))
            }
            None => Ok(Vec::new()),
        }
    }

    /// sub/gsub: replace in `target` (an lvalue, default $0).
    fn substitute(&mut self, args: &[Expr], global: bool) -> Res<Value> {
        if args.len() < 2 {
            return fatal("sub/gsub: not enough arguments");
        }
        let re = self.regex_of(&args[0])?;
        let repl = self.arg_text(args, 1)?;
        let field0 = Expr::Field(alloc::boxed::Box::new(Expr::Num(0.0)));
        let target = args.get(2).unwrap_or(&field0);
        let text = {
            let v = self.eval(target)?;
            v.text(&self.convfmt())
        };
        let mut out = Vec::new();
        let mut count = 0;
        let mut pos = 0;
        let mut copied = 0;
        let mut last_end: Option<usize> = None;
        while pos <= text.len() {
            let Some((a, b)) = re.find_at(&text, pos).and_then(|c| c[0]) else { break };
            if a == b && last_end == Some(a) {
                if a >= text.len() {
                    break;
                }
                pos = a + 1;
                continue;
            }
            out.extend_from_slice(&text[copied..a]);
            let mut k = 0;
            while k < repl.len() {
                match repl[k] {
                    b'\\' if repl.get(k + 1) == Some(&b'&') => {
                        out.push(b'&');
                        k += 2;
                    }
                    b'\\' if repl.get(k + 1) == Some(&b'\\') => {
                        out.push(b'\\');
                        k += 2;
                    }
                    b'&' => {
                        out.extend_from_slice(&text[a..b]);
                        k += 1;
                    }
                    c => {
                        out.push(c);
                        k += 1;
                    }
                }
            }
            copied = b;
            count += 1;
            last_end = Some(b);
            if !global {
                break;
            }
            pos = if b > a { b } else { b + 1 };
        }
        if count > 0 {
            out.extend_from_slice(&text[copied.min(text.len())..]);
            self.assign(target, Value::Str(out))?;
        }
        Ok(Value::Num(count as f64))
    }

    fn gensub(&mut self, args: &[Expr]) -> Res<Value> {
        if args.len() < 3 {
            return fatal("gensub: not enough arguments");
        }
        let re = self.regex_of(&args[0])?;
        let repl = self.arg_text(args, 1)?;
        let how = self.eval(&args[2])?;
        let conv = self.convfmt();
        let how_t = how.text(&conv);
        let (global, nth) = if how_t.first().is_some_and(|c| *c == b'g' || *c == b'G') {
            (true, 1)
        } else {
            (false, (how.num() as usize).max(1))
        };
        let text = match args.get(3) {
            Some(t) => self.eval(t)?.text(&conv),
            None => self.record.clone(),
        };
        let mut out = Vec::new();
        let (mut pos, mut copied, mut count) = (0, 0, 0);
        let mut last_end: Option<usize> = None;
        while pos <= text.len() {
            let Some(c) = re.find_at(&text, pos) else { break };
            let (a, b) = c[0].unwrap_or((pos, pos));
            if a == b && last_end == Some(a) {
                if a >= text.len() {
                    break;
                }
                pos = a + 1;
                continue;
            }
            count += 1;
            if global || count == nth {
                out.extend_from_slice(&text[copied..a]);
                let mut k = 0;
                while k < repl.len() {
                    match repl[k] {
                        b'\\' if repl.get(k + 1).is_some_and(u8::is_ascii_digit) => {
                            let g = (repl[k + 1] - b'0') as usize;
                            if let Some(Some((x, y))) = c.get(g) {
                                out.extend_from_slice(&text[*x..*y]);
                            }
                            k += 2;
                        }
                        b'\\' if repl.get(k + 1) == Some(&b'&') => {
                            out.push(b'&');
                            k += 2;
                        }
                        b'&' => {
                            out.extend_from_slice(&text[a..b]);
                            k += 1;
                        }
                        ch => {
                            out.push(ch);
                            k += 1;
                        }
                    }
                }
                copied = b;
                if !global {
                    break;
                }
            }
            last_end = Some(b);
            pos = if b > a { b } else { b + 1 };
        }
        out.extend_from_slice(&text[copied.min(text.len())..]);
        Ok(Value::Str(out))
    }

    fn builtin(&mut self, name: &str, args: &[Expr]) -> Res<Value> {
        let conv = self.convfmt();
        Ok(match name {
            "length" => match args.first() {
                None => Value::Num(self.chars(&self.record) as f64),
                Some(Expr::Var(v)) if matches!(self.cell(*v), Cell::Arr(_)) => {
                    let a = self.array(*v)?;
                    Value::Num(a.borrow().len() as f64)
                }
                // A subarray's length is its element count.
                Some(e @ Expr::Index(v, path)) => match self.elem_cell(*v, path)? {
                    Some(Cell::Arr(a)) => Value::Num(a.borrow().len() as f64),
                    _ => {
                        let v = self.eval(e)?;
                        Value::Num(self.chars(&v.text(&conv)) as f64)
                    }
                },
                Some(e) => {
                    let v = self.eval(e)?;
                    Value::Num(self.chars(&v.text(&conv)) as f64)
                }
            },
            "substr" => {
                let s = self.arg_text(args, 0)?;
                let m = self.arg_num(args, 1)?;
                let len = self.chars(&s) as f64;
                let start = if m.is_nan() { 1.0 } else { math::trunc(m).max(1.0) };
                let end = match args.get(2) {
                    Some(_) => {
                        let n = self.arg_num(args, 2)?;
                        if n.is_nan() || n <= 0.0 {
                            return Ok(Value::Str(Vec::new()));
                        }
                        // Both truncated, the start first raised to 1 (as gawk
                        // was seen to take fractions).
                        let n = math::trunc(n);
                        (start + n).min(len + 1.0)
                    }
                    None => len + 1.0,
                };
                if start > len || end <= start {
                    Value::Str(Vec::new())
                } else {
                    let (a, b) = (self.byte_of(&s, start as usize - 1), self.byte_of(&s, end as usize - 1));
                    Value::Str(s[a..b].to_vec())
                }
            }
            "index" => {
                let mut s = self.arg_text(args, 0)?;
                let mut t = self.arg_text(args, 1)?;
                if self.icase() {
                    s.make_ascii_lowercase();
                    t.make_ascii_lowercase();
                }
                let i = if t.is_empty() {
                    0
                } else {
                    s.windows(t.len()).position(|w| w == t.as_slice()).map_or(0, |i| self.chars(&s[..i]) + 1)
                };
                Value::Num(i as f64)
            }
            "split" => {
                let s = self.arg_text(args, 0)?;
                if !matches!(args.get(1), Some(Expr::Var(_) | Expr::Index(..))) {
                    return fatal("split: second argument is not an array");
                }
                let parts = match args.get(2) {
                    Some(Expr::Regex(i)) => {
                        let r = self.static_re(*i);
                        let mut cache = |_: &[u8]| Some(r.clone());
                        split_with(&s, b"\x00regex", false, &mut cache)
                    }
                    Some(e) => {
                        let fs = {
                            let v = self.eval(e)?;
                            v.text(&conv)
                        };
                        let mut re = self.re_cache();
                        split_with(&s, &fs, false, &mut re)
                    }
                    None => {
                        let fs = self.global_text(FS);
                        let mut re = self.re_cache();
                        split_with(&s, &fs, false, &mut re)
                    }
                };
                if matches!(args.get(3), Some(Expr::Var(_) | Expr::Index(..))) {
                    let fs = match args.get(2) {
                        Some(Expr::Regex(i)) => self.prog.regexes[*i].clone(),
                        Some(e) => {
                            let v = self.eval(e)?;
                            v.text(&conv)
                        }
                        None => self.global_text(FS),
                    };
                    let seps = self.separators(&s, &fs, matches!(args.get(2), Some(Expr::Regex(_))))?;
                    let sa = self.array_arg(args.get(3), "split")?;
                    let mut sa = sa.borrow_mut();
                    sa.clear();
                    for (i, t) in seps {
                        sa.insert(alloc::format!("{i}").into_bytes(), Cell::from(Value::Str(t)));
                    }
                }
                let n = parts.len();
                let a = self.array_arg(args.get(1), "split")?;
                fill(&a, parts, 1);
                Value::Num(n as f64)
            }
            "and" | "or" | "xor" => {
                if args.len() < 2 {
                    return fatal(alloc::format!("{name}: called with less than two arguments"));
                }
                let mut acc = None;
                for i in 0..args.len() {
                    let n = self.bits_arg(name, args, i)?;
                    acc = Some(match (acc, name) {
                        (None, _) => n,
                        (Some(a), "and") => a & n,
                        (Some(a), "or") => a | n,
                        (Some(a), _) => a ^ n,
                    });
                }
                Value::Num(acc.unwrap_or(0) as f64)
            }
            // gawk's numbers are doubles: 53 bits.
            "compl" => Value::Num((!self.bits_arg(name, args, 0)? & ((1 << 53) - 1)) as f64),
            "lshift" | "rshift" => {
                let n = self.bits_arg(name, args, 0)?;
                let by = self.bits_arg(name, args, 1)?.min(64) as u32;
                let r = if name == "lshift" { n.checked_shl(by) } else { n.checked_shr(by) };
                Value::Num(r.unwrap_or(0) as f64)
            }
            "strtonum" => match args.first() {
                Some(e) => match self.eval(e)? {
                    Value::Num(n) => Value::Num(n),
                    v => Value::Num(strtonum(&v.text(&conv))),
                },
                None => return fatal("strtonum: not enough arguments"),
            },
            "typeof" => {
                let kind = |v: &Value| match v {
                    Value::Num(_) => "number",
                    Value::Str(_) => "string",
                    Value::StrNum(_) => "strnum",
                    Value::Uninit => "untyped",
                    Value::Unassigned => "unassigned",
                    Value::Regex(_) => "regexp",
                    Value::Big(_) => "number",
                };
                let t = match args.first() {
                    Some(Expr::Var(v)) if matches!(self.cell(*v), Cell::Arr(_)) => "array",
                    // A variable's own kind: read before it was set, it is
                    // "unassigned" (without reading it now).
                    Some(Expr::Var(v)) if *v != Var::Global(NF) => match self.cell(*v) {
                        Cell::Val(x) => kind(x),
                        Cell::Arr(_) => "array",
                    },
                    // Asking about an element does not make it.
                    Some(Expr::Index(v, path)) => match self.elem_cell(*v, path)? {
                        None => "untyped",
                        Some(Cell::Arr(_)) => "array",
                        Some(Cell::Val(x)) => kind(&x),
                    },
                    Some(e) => kind(&self.eval(e)?),
                    None => return fatal("typeof: not enough arguments"),
                };
                Value::Str(t.as_bytes().to_vec())
            }
            "isarray" => {
                let array = match args.first() {
                    Some(Expr::Var(v)) => matches!(self.cell(*v), Cell::Arr(_)),
                    Some(Expr::Index(v, path)) => matches!(self.elem_cell(*v, path)?, Some(Cell::Arr(_))),
                    _ => false,
                };
                Value::Num(array as i32 as f64)
            }
            "mktime" => {
                let spec = self.arg_text(args, 0)?;
                let utc = match args.get(1) {
                    Some(e) => self.eval(e)?.truthy(),
                    None => false,
                };
                Value::Num(mktime(&spec, utc) as f64)
            }
            "patsplit" => {
                let s = self.arg_text(args, 0)?;
                if !matches!(args.get(1), Some(Expr::Var(_) | Expr::Index(..))) {
                    return fatal("patsplit: second argument is not an array");
                }
                let re = match args.get(2) {
                    Some(e) => self.regex_of(e)?,
                    None => {
                        let p = self.global_text(FPAT);
                        self.dyn_regex(&p)?
                    }
                };
                let (fields, seps) = pattern_split(&s, &re);
                let n = fields.len();
                let a = self.array_arg(args.get(1), "patsplit")?;
                fill(&a, fields, 1);
                if matches!(args.get(3), Some(Expr::Var(_) | Expr::Index(..))) {
                    let sa = self.array_arg(args.get(3), "patsplit")?;
                    fill(&sa, if n == 0 { Vec::new() } else { seps }, 0);
                }
                Value::Num(n as f64)
            }
            "asort" => self.asort(args, false)?,
            "asorti" => self.asort(args, true)?,
            "sub" => self.substitute(args, false)?,
            "gsub" => self.substitute(args, true)?,
            "gensub" => self.gensub(args)?,
            "match" => {
                let s = self.arg_text(args, 0)?;
                let re = match args.get(1) {
                    Some(e) => self.regex_of(e)?,
                    None => return fatal("match: not enough arguments"),
                };
                let c = re.find_at(&s, 0);
                let (start, len) = match c.as_ref().and_then(|c| c[0]) {
                    Some((a, b)) => (self.chars(&s[..a]) as f64 + 1.0, self.chars(&s[a..b]) as f64),
                    None => (0.0, -1.0),
                };
                self.globals[RSTART] = Cell::Val(Value::Num(start));
                self.globals[RLENGTH] = Cell::Val(Value::Num(len));
                if matches!(args.get(2), Some(Expr::Var(_) | Expr::Index(..))) {
                    let a = self.array_arg(args.get(2), "match")?;
                    let mut a = a.borrow_mut();
                    a.clear();
                    if let Some(c) = c {
                        let sep = self.global_text(SUBSEP);
                        for (g, m) in c.iter().enumerate() {
                            if let Some((x, y)) = m {
                                let k = alloc::format!("{g}").into_bytes();
                                a.insert(k.clone(), Cell::from(Value::from_input(s[*x..*y].to_vec())));
                                let (at, n) = (self.chars(&s[..*x]) as f64 + 1.0, self.chars(&s[*x..*y]) as f64);
                                a.insert([k.as_slice(), &sep, b"start"].concat(), Cell::from(Value::Num(at)));
                                a.insert([k.as_slice(), &sep, b"length"].concat(), Cell::from(Value::Num(n)));
                            }
                        }
                    }
                }
                Value::Num(start)
            }
            "sprintf" => {
                if args.is_empty() {
                    return fatal("sprintf: no format");
                }
                let fmt = self.arg_text(args, 0)?;
                let mut vals = Vec::new();
                for a in &args[1..] {
                    vals.push(self.eval(a)?);
                }
                Value::Str(sprintf(&fmt, &vals, &conv))
            }
            "sin" => Value::Num(math::sin(self.arg_num(args, 0)?)),
            "cos" => Value::Num(math::cos(self.arg_num(args, 0)?)),
            "atan2" => {
                let y = self.arg_num(args, 0)?;
                let x = self.arg_num(args, 1)?;
                Value::Num(math::atan2(y, x))
            }
            "exp" => Value::Num(math::exp(self.arg_num(args, 0)?)),
            "log" => Value::Num(math::log(self.arg_num(args, 0)?)),
            "sqrt" => Value::Num(math::sqrt(self.arg_num(args, 0)?)),
            "int" => match args.first() {
                Some(e) => {
                    let v = self.eval(e)?;
                    match (&v, self.bignum) {
                        (Value::Big(_), _) => v,
                        (_, true) => {
                            Big::from_f64(math::trunc(v.num())).map_or(Value::Num(math::trunc(v.num())), Value::Big)
                        }
                        _ => Value::Num(math::trunc(v.num())),
                    }
                }
                None => Value::Num(0.0),
            },
            "rand" => {
                // xorshift64*: a fixed sequence for a given seed.
                let mut x = self.rand_state;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                self.rand_state = x;
                let r = x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11;
                Value::Num(r as f64 / (1u64 << 53) as f64)
            }
            "srand" => {
                let prev = self.seed;
                let s = match args.first() {
                    Some(e) => self.eval(e)?.num(),
                    None => slate_rt::time::unix() as f64,
                };
                self.seed = s;
                self.rand_state = (s as i64 as u64) ^ 0x9E37_79B9_7F4A_7C15;
                if self.rand_state == 0 {
                    self.rand_state = 1;
                }
                Value::Num(prev)
            }
            "tolower" => Value::Str(self.arg_text(args, 0)?.to_ascii_lowercase()),
            "toupper" => Value::Str(self.arg_text(args, 0)?.to_ascii_uppercase()),
            "system" => {
                let cmd = self.arg_text(args, 0)?;
                self.flush();
                let argv = alloc::vec![b"sh".to_vec(), b"-c".to_vec(), cmd];
                let st = process::run(b"/bin/sh", &argv)
                    .map_or(-1, |s| process::exited(s).or_else(|| process::signaled(s).map(|g| 256 + g)).unwrap_or(-1));
                Value::Num(st as f64)
            }
            "close" => {
                let n = self.arg_text(args, 0)?;
                Value::Num(self.close(&n) as f64)
            }
            "fflush" => {
                self.flush();
                Value::Num(0.0)
            }
            "systime" => Value::Num(slate_rt::time::unix() as f64),
            "strftime" => {
                let fmt = match args.first() {
                    Some(_) => self.arg_text(args, 0)?,
                    None => b"%a %b %e %H:%M:%S %Z %Y".to_vec(),
                };
                let t = if args.len() > 1 { self.arg_num(args, 1)? as i64 } else { slate_rt::time::unix() };
                // gawk's third argument asks for UTC.
                let utc = args.len() > 2 && self.arg_num(args, 2)? != 0.0;
                let tm = if utc { slate_rt::time::gmtime(t) } else { slate_rt::tz::localtime(t) };
                let mut s = String::new();
                slate_rt::time::format(&tm, &String::from_utf8_lossy(&fmt), &mut s);
                Value::Str(s.into_bytes())
            }
            // gettext (gawk manual, "Internationalization"): with no
            // message catalogs, the text as it is.
            "dcgettext" => Value::Str(self.arg_text(args, 0)?),
            "dcngettext" => {
                let n = self.arg_num(args, 2)?;
                Value::Str(self.arg_text(args, if n == 1.0 { 0 } else { 1 })?)
            }
            "bindtextdomain" => Value::Str(self.arg_text(args, 0)?),
            n if is_extension(n) => self.extension(n, args)?,
            other => return fatal(alloc::format!("function `{other}' is not supported")),
        })
    }

    /// Set ERRNO to `e`'s text; -1 for the caller to return.
    fn errno(&mut self, e: impl core::fmt::Display) -> Value {
        self.globals[ERRNO] = Cell::Val(Value::Str(alloc::format!("{e}").into_bytes()));
        Value::Num(-1.0)
    }

    /// The functions of the extensions built in (`@load`, ADR 0165),
    /// behaving as gawk's bundled ones were seen to.
    fn extension(&mut self, name: &str, args: &[Expr]) -> Res<Value> {
        Ok(match name {
            // ordchr: bytes, as gawk's are.
            "ord" => Value::Num(self.arg_text(args, 0)?.first().copied().unwrap_or(0).into()),
            "chr" => Value::Str(alloc::vec![self.arg_num(args, 0)? as i64 as u8]),
            "gettimeofday" => {
                let (s, ns) = slate_rt::time::now(slate_rt::time::CLOCK_REALTIME);
                Value::Num(s as f64 + (ns / 1000) as f64 / 1e6)
            }
            "sleep" => {
                let t = self.arg_num(args, 0)?;
                if t < 0.0 {
                    return Ok(self.errno("sleep: argument is negative"));
                }
                slate_rt::time::sleep_ns((t * 1e9) as u64);
                Value::Num(0.0)
            }
            "readfile" => {
                let f = self.arg_text(args, 0)?;
                match fs::read_file(&f) {
                    Ok(t) => Value::Str(t),
                    Err(e) => {
                        self.errno(e);
                        Value::Str(Vec::new())
                    }
                }
            }
            "chdir" => match fs::chdir(&self.arg_text(args, 0)?) {
                Ok(()) => Value::Num(0.0),
                Err(e) => self.errno(e),
            },
            "stat" => {
                let f = self.arg_text(args, 0)?;
                let follow = match args.get(2) {
                    Some(e) => self.eval(e)?.truthy(),
                    None => false,
                };
                let a = self.array_arg(args.get(1), "stat")?;
                a.borrow_mut().clear();
                let st = if follow { fs::stat(&f) } else { fs::lstat(&f) };
                let st = match st {
                    Ok(st) => st,
                    Err(e) => return Ok(self.errno(e)),
                };
                let kind = match st.mode & fs::S_IFMT {
                    fs::S_IFDIR => "directory",
                    fs::S_IFLNK => "symlink",
                    fs::S_IFCHR => "chardev",
                    fs::S_IFBLK => "blockdev",
                    fs::S_IFIFO => "fifo",
                    fs::S_IFSOCK => "socket",
                    _ => "file",
                };
                let mut a = a.borrow_mut();
                let mut put = |k: &str, v: Value| {
                    a.insert(k.as_bytes().to_vec(), Cell::Val(v));
                };
                let n = |x: f64| Value::Num(x);
                put("name", Value::Str(f.clone()));
                put("dev", n(st.dev as f64));
                put("ino", n(st.ino as f64));
                put("mode", n(st.mode.into()));
                put("nlink", n(st.nlink as f64));
                put("uid", n(st.uid.into()));
                put("gid", n(st.gid.into()));
                put("size", n(st.size as f64));
                put("blocks", n(st.blocks as f64));
                put("blksize", n(st.blksize as f64));
                put("devbsize", n(512.0));
                put("atime", n(st.atime as f64));
                put("mtime", n(st.mtime as f64));
                put("ctime", n(st.ctime as f64));
                put("pmode", Value::Str(crate::ls::mode_string(st.mode).to_vec()));
                put("type", Value::Str(kind.as_bytes().to_vec()));
                if kind == "chardev" || kind == "blockdev" {
                    put("rdev", n(st.rdev as f64));
                    put("major", n(((st.rdev >> 8) & 0xfff) as f64));
                    put("minor", n(((st.rdev & 0xff) | ((st.rdev >> 12) & 0xfff00)) as f64));
                }
                if kind == "symlink"
                    && let Ok(l) = fs::readlink(&f)
                {
                    put("linkval", Value::Str(l));
                }
                Value::Num(0.0)
            }
            "statvfs" => {
                let f = self.arg_text(args, 0)?;
                let a = self.array_arg(args.get(1), "statvfs")?;
                a.borrow_mut().clear();
                let st = match fs::statfs(&f) {
                    Ok(st) => st,
                    Err(e) => return Ok(self.errno(e)),
                };
                let mut a = a.borrow_mut();
                for (k, v) in [
                    ("bsize", st.block_size as f64),
                    ("frsize", st.fragment_size as f64),
                    ("blocks", st.blocks as f64),
                    ("bfree", st.free as f64),
                    ("bavail", st.available as f64),
                    ("files", st.files as f64),
                    ("ffree", st.free_files as f64),
                    ("favail", st.free_files as f64),
                    ("fsid", st.fsid as f64),
                    ("namemax", st.name_max as f64),
                ] {
                    a.insert(k.as_bytes().to_vec(), Cell::Val(Value::Num(v)));
                }
                Value::Num(0.0)
            }
            "fnmatch" => {
                let pat = self.arg_text(args, 0)?;
                let s = self.arg_text(args, 1)?;
                let f = self.arg_num(args, 2)? as i64;
                // FNM's values (gawk's FNM array, observed): PATHNAME 1,
                // NOESCAPE 2, PERIOD 4, LEADING_DIR 8, CASEFOLD 16.
                let flags =
                    slate_regex::fnmatch::Flags { pathname: f & 1 != 0, period: f & 4 != 0, casefold: f & 16 != 0 };
                Value::Num(if slate_regex::fnmatch::fnmatch_with(&pat, &s, flags) { 0.0 } else { 1.0 })
            }
            "fork" => {
                self.flush();
                match slate_rt::process::fork() {
                    Ok(pid) => Value::Num(pid.into()),
                    Err(e) => self.errno(e),
                }
            }
            "waitpid" => {
                let pid = self.arg_num(args, 0)? as i32;
                match slate_rt::process::wait(pid, 0) {
                    Ok(_) => Value::Num(0.0),
                    Err(e) => self.errno(e),
                }
            }
            "wait" => match slate_rt::process::wait(-1, 0) {
                Ok((pid, _)) => Value::Num(pid.into()),
                Err(e) => self.errno(e),
            },
            "inplace::begin" => {
                let (file, suffix) = (self.arg_text(args, 0)?, self.arg_text(args, 1)?);
                self.inplace_begin(&file, &suffix);
                Value::Uninit
            }
            "inplace::end" => {
                let (file, suffix) = (self.arg_text(args, 0)?, self.arg_text(args, 1)?);
                self.inplace_end(&file, &suffix);
                Value::Uninit
            }
            other => return fatal(alloc::format!("function `{other}' is not supported")),
        })
    }

    /// inplace::begin: standard output goes to a new file beside `file`
    /// until inplace::end (gawk's inplace extension; `-i inplace`).
    fn inplace_begin(&mut self, file: &[u8], _suffix: &[u8]) {
        if file.is_empty() || file == b"-" || self.inplace.is_some() {
            return;
        }
        let st = match fs::stat(file) {
            Ok(st) if st.mode & fs::S_IFMT == fs::S_IFREG => st,
            _ => {
                slate_rt::eprintln!("awk: warning: inplace::begin: cannot edit `{}' in place", slate_rt::lossy(file));
                return;
            }
        };
        let tmp = [file, b".awkXXXX"].concat();
        let tmp = [tmp.as_slice(), alloc::format!("{}", process::getpid()).as_bytes()].concat();
        let Ok(fd) = fs::open(&tmp, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC, st.mode & 0o7777) else {
            slate_rt::eprintln!("awk: warning: inplace::begin: cannot make a file beside `{}'", slate_rt::lossy(file));
            return;
        };
        self.flush();
        let saved = process::dup(1).unwrap_or(-1);
        let _ = process::dup2(fd, 1);
        let _ = io::close(fd);
        self.inplace = Some((saved, tmp));
    }

    /// inplace::end: the new file replaces `file` (the old one kept as
    /// `file` + `suffix` when there is a suffix).
    fn inplace_end(&mut self, file: &[u8], suffix: &[u8]) {
        let Some((saved, tmp)) = self.inplace.take() else { return };
        self.flush();
        if saved >= 0 {
            let _ = process::dup2(saved, 1);
            let _ = io::close(saved);
        }
        if !suffix.is_empty() {
            let backup = [file, suffix].concat();
            let _ = fs::unlink(&backup);
            let _ = fs::link(file, &backup);
        }
        if let Err(e) = fs::rename(&tmp, file) {
            slate_rt::eprintln!("awk: warning: inplace::end: cannot replace `{}': {e}", slate_rt::lossy(file));
            let _ = fs::unlink(&tmp);
        }
    }

    // --- statements ----------------------------------------------------------------

    fn output_value(&mut self, v: &Value) -> Vec<u8> {
        match v {
            Value::Num(n) => num_to_str(*n, &self.global_text(OFMT)),
            other => other.text(b"%.6g"),
        }
    }

    pub fn exec_block(&mut self, stmts: &[Stmt]) -> Res<()> {
        for s in stmts {
            self.exec(s)?;
        }
        Ok(())
    }

    fn exec(&mut self, s: &Stmt) -> Res<()> {
        match s {
            Stmt::Expr(e) => {
                self.eval(e)?;
            }
            Stmt::Print(args, redir) => {
                let mut line = Vec::new();
                if args.is_empty() {
                    line.extend_from_slice(&self.record);
                } else {
                    let ofs = self.global_text(OFS);
                    for (i, a) in args.iter().enumerate() {
                        if i > 0 {
                            line.extend_from_slice(&ofs);
                        }
                        let v = self.eval(a)?;
                        line.extend_from_slice(&self.output_value(&v));
                    }
                }
                line.extend_from_slice(&self.global_text(ORS));
                self.write_to(redir, &line)?;
            }
            Stmt::Printf(args, redir) => {
                let fmt = {
                    let v = self.eval(&args[0])?;
                    v.text(&self.convfmt())
                };
                let mut vals = Vec::new();
                for a in &args[1..] {
                    vals.push(self.eval(a)?);
                }
                let out = sprintf(&fmt, &vals, &self.convfmt());
                self.write_to(redir, &out)?;
            }
            Stmt::If(c, a, b) => {
                if self.eval(c)?.truthy() {
                    self.exec(a)?;
                } else if let Some(b) = b {
                    self.exec(b)?;
                }
            }
            Stmt::While(c, body) => {
                while self.eval(c)?.truthy() {
                    match self.exec(body) {
                        Err(Flow::Break) => break,
                        Err(Flow::Continue) | Ok(()) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
            Stmt::Do(body, c) => loop {
                match self.exec(body) {
                    Err(Flow::Break) => break,
                    Err(Flow::Continue) | Ok(()) => {}
                    Err(e) => return Err(e),
                }
                if !self.eval(c)?.truthy() {
                    break;
                }
            },
            Stmt::For(init, cond, step, body) => {
                if let Some(i) = init {
                    self.exec(i)?;
                }
                loop {
                    if let Some(c) = cond
                        && !self.eval(c)?.truthy()
                    {
                        break;
                    }
                    match self.exec(body) {
                        Err(Flow::Break) => break,
                        Err(Flow::Continue) | Ok(()) => {}
                        Err(e) => return Err(e),
                    }
                    if let Some(st) = step {
                        self.exec(st)?;
                    }
                }
            }
            Stmt::ForIn(var, arr, path, body) => {
                let a = self.array_at(*arr, path)?;
                let keys = self.traversal(&a)?;
                for k in keys {
                    if !a.borrow().contains_key(&k) {
                        continue;
                    }
                    self.set_var(*var, Value::Str(k))?;
                    match self.exec(body) {
                        Err(Flow::Break) => break,
                        Err(Flow::Continue) | Ok(()) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
            Stmt::Block(v) => self.exec_block(v)?,
            Stmt::Switch(e, cases) => {
                let v = self.eval(e)?;
                let mut start = None;
                for (i, (c, _)) in cases.iter().enumerate() {
                    if self.case_matches(c, &v) {
                        start = Some(i);
                        break;
                    }
                }
                let start = start.or_else(|| cases.iter().position(|(c, _)| matches!(c, Case::Default)));
                if let Some(start) = start {
                    // Control falls through the later cases until break.
                    for (_, body) in &cases[start..] {
                        match self.exec_block(body) {
                            Err(Flow::Break) => return Ok(()),
                            r => r?,
                        }
                    }
                }
            }
            Stmt::Next => return Err(Flow::Next),
            Stmt::NextFile => return Err(Flow::NextFile),
            Stmt::Exit(e) => {
                if let Some(e) = e {
                    self.exit_code = self.eval(e)?.num() as i32;
                }
                return Err(Flow::Exit);
            }
            Stmt::Return(e) => {
                let v = match e {
                    Some(e) => self.eval(e)?,
                    None => Value::Uninit,
                };
                return Err(Flow::Return(v));
            }
            Stmt::Break => return Err(Flow::Break),
            Stmt::Continue => return Err(Flow::Continue),
            Stmt::Delete(v, path) => match path.split_last() {
                None => self.array(*v)?.borrow_mut().clear(),
                Some((last, up)) => {
                    let a = self.array_at(*v, up)?;
                    let k = self.subscript(last)?;
                    a.borrow_mut().remove(&k);
                }
            },
        }
        Ok(())
    }

    fn pattern(&mut self, ri: usize) -> Res<bool> {
        let rule = &self.prog.rules[ri];
        Ok(match &rule.pattern {
            Pattern::All => true,
            Pattern::Expr(e) => self.eval(e)?.truthy(),
            Pattern::Range(a, b) => {
                if self.ranges[ri] {
                    if self.eval(b)?.truthy() {
                        self.ranges[ri] = false;
                    }
                    true
                } else if self.eval(a)?.truthy() {
                    self.ranges[ri] = !self.eval(b)?.truthy();
                    true
                } else {
                    false
                }
            }
        })
    }

    /// Run the whole program; the exit status.
    pub fn run(&mut self) -> i32 {
        let prog = self.prog;
        let mut exiting = false;
        match self.exec_block(&prog.begin) {
            Ok(()) => {}
            Err(Flow::Exit) => exiting = true,
            Err(Flow::Fatal(m)) => return self.die(&m),
            Err(_) => {}
        }
        let reads = !prog.rules.is_empty() || !prog.end.is_empty() || !prog.beginfile.is_empty();
        if !exiting && (reads || !prog.endfile.is_empty()) {
            'records: loop {
                let rec = match self.next_main() {
                    Ok(Some(rec)) => rec,
                    Ok(None) => break,
                    Err(Flow::Exit) => break,
                    Err(Flow::Fatal(m)) => return self.die(&m),
                    Err(_) => continue,
                };
                self.set_record(rec);
                for (ri, rule) in prog.rules.iter().enumerate() {
                    let hit = match self.pattern(ri) {
                        Ok(h) => h,
                        Err(Flow::Fatal(m)) => return self.die(&m),
                        Err(_) => false,
                    };
                    if !hit {
                        continue;
                    }
                    let r = match &rule.action {
                        Some(a) => self.exec_block(a),
                        None => {
                            let mut line = self.record.clone();
                            line.extend_from_slice(&self.global_text(ORS));
                            self.write_to(&None, &line)
                        }
                    };
                    match r {
                        Ok(()) => {}
                        Err(Flow::Next) => continue 'records,
                        Err(Flow::NextFile) => match self.end_file() {
                            Ok(()) => continue 'records,
                            Err(Flow::Fatal(m)) => return self.die(&m),
                            Err(_) => break 'records,
                        },
                        Err(Flow::Exit) => {
                            exiting = true;
                            break 'records;
                        }
                        Err(Flow::Fatal(m)) => return self.die(&m),
                        Err(_) => {}
                    }
                }
            }
        }
        let _ = exiting;
        if let Err(Flow::Fatal(m)) = self.exec_block(&prog.end) {
            return self.die(&m);
        }
        self.close_all();
        self.exit_code
    }

    fn die(&mut self, m: &str) -> i32 {
        self.close_all();
        crate::util::error(alloc::format!("fatal: {m}"));
        2
    }
}

/// Escape sequences in -v and command-line assignments.
pub fn process_escapes(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'\\' && i + 1 < s.len() {
            let (b, n) = super::lex::escape(s, i + 1);
            out.extend_from_slice(&b);
            i += 1 + n.max(1);
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    out
}
