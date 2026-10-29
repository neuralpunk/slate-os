// SPDX-License-Identifier: MIT OR Apache-2.0

//! The mockups' scenes (docs/design/slateos-wm-mockups.zip), drawn with Strata's
//! surfaces and sample window contents, fingerprinted against
//! tests/screens.txt. `SLATE_UI_OUT=DIR` saves them as PNGs to look at;
//! `SLATE_UI_BLESS=1` records a reviewed change.

use std::format;
use std::string::{String, ToString};
use std::vec::Vec;

use slate_ui::graphite::Palette;
use slate_ui::icon::Icon;
use slate_ui::paint::Painter;
use slate_ui::text::GlyphCache;
use slate_ui::ui::Area;
use slate_ui::{Canvas, Color};

use crate::desktop::{Extras, Status};
use crate::draw::{self, Approval, ApprovalFocus, Launcher, Row, Section, TitleButton};
use crate::fonts::{FILES, Fonts};
use crate::wm::{Command, WinId, Wm};

fn fonts() -> Fonts<'static> {
    let read = |n: &str| -> &'static [u8] {
        let p = format!("{}/../../assets/fonts/{n}", env!("CARGO_MANIFEST_DIR"));
        std::boxed::Box::leak(std::fs::read(p).unwrap().into_boxed_slice())
    };
    Fonts::new(FILES.map(read)).unwrap().with_serifs(crate::fonts::SERIF_FILES.map(read))
}

// --- sample contents (what apps would draw) -----------------------------

const EDITOR: &[&str] = &[
    "//! Round-robin scheduler for the Slate kernel.",
    "",
    "use crate::task::{Task, TaskState};",
    "use alloc::collections::VecDeque;",
    "",
    "pub struct Scheduler {",
    "    ready: VecDeque<Task>,",
    "    current: Option<Task>,",
    "    quantum: u32,",
    "}",
    "",
    "impl Scheduler {",
    "    pub fn new(quantum: u32) -> Self {",
    "        Self { ready: VecDeque::new(), current: None, quantum }",
    "    }",
    "",
    "    /// Pick the next runnable task, parking the current one.",
    "    pub fn tick(&mut self) -> Option<&Task> {",
    "        if let Some(mut task) = self.current.take() {",
    "            task.state = TaskState::Ready;",
    "            self.ready.push_back(task);",
    "        }",
    "        self.current = self.ready.pop_front();",
    "        self.current.as_ref()",
    "    }",
    "}",
];

const KEYWORDS: &[&str] = &["use", "pub", "struct", "impl", "fn", "if", "let", "mut", "self", "Self", "crate"];

/// One line of Rust in the monochrome syntax theme (§7): graphite's
/// greys on a dark palette, the Editor's own tokens (ink keywords, the
/// readable text greys) on a light one.
fn code_line(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, x: f32, top: f32, line: &str) {
    let size = 13.0;
    let light = pal.light();
    let (comment, keyword, upper, ident, punct) = if light {
        (pal.muted, pal.chalk, pal.text_1, pal.text_2, pal.text_4)
    } else {
        (Color::rgb(0x85837E), Color::rgb(0xE3E1DC), Color::rgb(0xD2D0CB), Color::rgb(0xB3B1AC), Color::rgb(0x7E7C78))
    };
    if line.trim_start().starts_with("//") {
        let st = p.style(&f.mono, size, comment);
        p.line(&st, x, top, 22.0, line);
        return;
    }
    let mut x = x;
    let mut word = String::new();
    let flush = |p: &mut Painter<'_>, x: &mut f32, word: &mut String| {
        if word.is_empty() {
            return;
        }
        let (face, c) = if KEYWORDS.contains(&word.as_str()) {
            (&f.mono_medium, keyword)
        } else if word.starts_with(|c: char| c.is_ascii_uppercase() || c.is_ascii_digit()) {
            (&f.mono, upper)
        } else {
            (&f.mono, ident)
        };
        let st = p.style(face, size, c);
        *x += p.line(&st, *x, top, 22.0, word);
        word.clear();
    };
    for ch in line.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            word.push(ch);
        } else {
            flush(p, &mut x, &mut word);
            let c = if ch == ' ' { ident } else { punct };
            let st = p.style(&f.mono, size, c);
            x += p.line(&st, x, top, 22.0, &ch.to_string());
        }
    }
    flush(p, &mut x, &mut word);
}

fn status_bar(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, c: Area, left: &[(&str, &str)], right: &str) {
    let bar = Area::new(c.x, c.bottom() - 26.0, c.w, 26.0);
    p.fill(Area::new(bar.x, bar.y, bar.w, 1.0), 0.0, pal.divider);
    let (key, label) = (p.style(&f.mono, 11.0, pal.text_1), p.style(&f.mono, 11.0, pal.muted));
    let mut x = bar.x + 20.0;
    for (k, l) in left {
        if !k.is_empty() {
            x += p.line(&key, x, bar.y + 1.0, 25.0, k) + 5.0;
        }
        x += p.line(&label, x, bar.y + 1.0, 25.0, l) + 18.0;
    }
    let rw = p.measure(&label, right);
    p.line(&label, bar.right() - 20.0 - rw, bar.y + 1.0, 25.0, right);
}

fn editor(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, c: Area) {
    let top = c.y + 14.0;
    for (i, l) in EDITOR.iter().enumerate() {
        let y = top + 22.0 * i as f32;
        let current = i == 19;
        if current {
            p.fill(Area::new(c.x, y, c.w, 22.0), 0.0, pal.line_current);
        }
        let num = format!("{}", i + 1);
        let st = p.style(&f.mono, 13.0, if current { pal.text_1 } else { pal.decor });
        let nw = p.measure(&st, &num);
        p.line(&st, c.x + 56.0 - nw, y, 22.0, &num);
        code_line(p, pal, f, c.x + 74.0, y, l);
        if current {
            let st = p.style(&f.mono, 13.0, pal.chalk);
            let w = p.measure(&st, l);
            p.fill(Area::new(c.x + 74.0 + w + 1.0, y + 3.0, 2.0, 16.0), 0.0, pal.chalk);
        }
    }
    status_bar(p, pal, f, c, &[("", "rust"), ("", "utf-8"), ("", "lf")], "ln 20, col 35");
}

fn terminal(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, c: Area) {
    let mut y = c.y + 14.0;
    let prompt = |p: &mut Painter<'_>, y: f32, cmd: &str| {
        let mut x = c.x + 16.0;
        x += p.line(&p.style(&f.mono_medium, 13.0, pal.chalk), x, y, 21.0, "alex@workstation");
        x += p.line(&p.style(&f.mono, 13.0, pal.muted), x, y, 21.0, " ~/slate");
        x += p.line(&p.style(&f.mono, 13.0, pal.inactive), x, y, 21.0, " $ ");
        x + p.line(&p.style(&f.mono, 13.0, pal.text_2), x, y, 21.0, cmd)
    };
    let pairs = |p: &mut Painter<'_>, y: &mut f32, rows: &[(&str, &str)]| {
        for (k, v) in rows {
            p.line(&p.style(&f.mono, 13.0, pal.muted), c.x + 16.0, *y, 21.0, k);
            p.line(&p.style(&f.mono, 13.0, pal.text_2), c.x + 124.0, *y, 21.0, v);
            *y += 21.0;
        }
    };
    prompt(p, y, "quarry install ripgrep");
    y += 21.0;
    pairs(
        p,
        &mut y,
        &[("resolving", "ripgrep 14.1.1"), ("verifying", "signature ok · quarry/main"), ("installed", "1 package")],
    );
    y += 21.0;
    prompt(p, y, "slate status");
    y += 21.0;
    pairs(
        p,
        &mut y,
        &[
            ("mode", "slate"),
            ("linux domain", "on"),
            ("system image", "signed, verified"),
            ("snapshots", "factory + 2 updates"),
        ],
    );
    y += 21.0;
    let end = prompt(p, y, "");
    p.fill(Area::new(end, y + 2.5, 8.0, 16.0), 0.0, pal.muted);
}

fn htop(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, c: Area) {
    let meter = |p: &mut Painter<'_>, x: f32, y: f32, label: &str, frac: f32, value: &str| {
        p.line(&p.style(&f.mono, 11.5, pal.muted), x, y, 21.0, label);
        let track = Area::new(x + 38.0, y + 8.0, 133.0, 5.0);
        p.fill(track, 3.0, pal.raised);
        p.fill(Area::new(track.x, track.y, track.w * frac, 5.0), 3.0, pal.text_2);
        let st = p.style(&f.mono, 11.5, pal.text_2);
        let vw = p.measure(&st, value);
        p.line(&st, x + 255.0 - vw, y, 21.0, value);
    };
    let (l, r) = (c.x + 16.0, c.x + c.w / 2.0 + 8.0);
    let y = c.y + 12.0;
    meter(p, l, y, "cpu0", 0.22, "22%");
    meter(p, r, y, "cpu1", 0.09, "9%");
    meter(p, l, y + 21.0, "cpu2", 0.31, "31%");
    meter(p, r, y + 21.0, "cpu3", 0.06, "6%");
    meter(p, l, y + 42.0, "mem", 0.34, "5.4G/16G");
    meter(p, r, y + 42.0, "swp", 0.0, "0K/4G");
    let cols = [0.0, 50.0, 103.0, 155.0, 207.0, 274.0];
    let head = Area::new(c.x, y + 72.0, c.w, 21.0);
    p.fill(head, 0.0, pal.header);
    for (i, h) in ["PID", "USER", "CPU%", "MEM%", "TIME", "COMMAND"].iter().enumerate() {
        p.line(&p.style(&f.mono, 11.5, pal.muted), l + cols[i], head.y, 21.0, h);
    }
    let rows = [
        ["214", "alex", "12.4", "3.1", "0:41.20", "firefox --new-window"],
        ["377", "alex", "4.8", "1.2", "0:07.91", "node server.js"],
        ["512", "alex", "1.1", "0.6", "0:02.33", "cargo build --release"],
        ["102", "alex", "0.7", "0.3", "0:01.42", "bash"],
        ["455", "alex", "0.3", "0.1", "0:00.21", "htop"],
    ];
    for (n, row) in rows.iter().enumerate() {
        let ry = head.bottom() + 21.0 * n as f32;
        // The rows in graphite's grey on a dark palette, `text_2` on a
        // light one; the selected row's text in `window` there (5:1 on
        // Sediment's terracotta).
        let colour = match (n, pal.light()) {
            (0, light) => {
                p.fill(Area::new(c.x, ry, c.w, 21.0), 0.0, pal.list_selected);
                if light { pal.window } else { pal.desktop }
            }
            (_, true) => pal.text_2,
            (_, false) => Color::rgb(0xB3B1AC),
        };
        for (i, cell) in row.iter().enumerate() {
            p.line(&p.style(&f.mono, 11.5, colour), l + cols[i], ry, 21.0, cell);
        }
    }
    status_bar(p, pal, f, c, &[("F1", "help"), ("F3", "search"), ("F6", "sort"), ("F9", "kill"), ("F10", "quit")], "");
}

// --- scenes -------------------------------------------------------------

/// The mockups' desktop as floating windows: the editor, a terminal and
/// htop (a Linux program), placed as in the mockup; `focused` is raised.
fn mockup_wm(w: f32, h: f32, focused: usize) -> (Wm, [WinId; 3]) {
    let mut wm = Wm::new(w, h);
    let ids = [
        wm.add("editor", Some("~/slate/kernel/src/sched.rs"), false),
        wm.add("terminal", Some("~/slate"), false),
        wm.add("htop", None, true),
    ];
    let rects = [
        Area::new(10.0, 42.0, 846.0, 848.0),
        Area::new(866.0, 42.0, 564.0, 470.0),
        Area::new(866.0, 522.0, 564.0, 368.0),
    ];
    for ((id, r), icon) in ids.iter().zip(rects).zip([Some(Icon::Document), Some(Icon::Terminal), None]) {
        let win = wm.get_mut(*id).unwrap();
        win.rect = r;
        win.icon = icon;
    }
    wm.get_mut(ids[1]).unwrap().accent = Some(slate_ui::themes::Stratum::Ochre);
    wm.focus(ids[focused]);
    (wm, ids)
}

fn status() -> Status {
    Status {
        clock: "Mon 19 Oct  14:32".into(),
        time: "14:32".into(),
        date: "Monday 19 October".into(),
        network: Some(true),
        battery: Some(84),
        updates: 0,
    }
}

fn contents<'a>(pal: &'a Palette, f: &'a Fonts<'a>, ids: [WinId; 3]) -> impl FnMut(&mut Painter<'_>, WinId, Area) + 'a {
    // Sediment's terminal is dark (ADR 0167).
    let term = if *pal == Palette::SEDIMENT { Palette::SEDIMENT_TERMINAL } else { *pal };
    move |p, id, c| {
        if id == ids[0] {
            editor(p, pal, f, c)
        } else if id == ids[1] {
            p.fill(c, 0.0, term.window);
            terminal(p, &term, f, c)
        } else {
            htop(p, pal, f, c)
        }
    }
}

fn desktop(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, focused: usize, extras: Extras) {
    let (w, h) = p.size();
    let (mut wm, ids) = mockup_wm(w, h, focused);
    wm.shape(pal.shape.title_h, pal.shape.bar_h);
    crate::desktop::desktop(p, pal, f, &wm, &status(), extras, &mut contents(pal, f, ids));
}

const APPS: &[Row<'static>] = &[
    Row { icon: Icon::Globe, name: "Firefox", linux: true, meta: "app", comment: "Browse the web" },
    Row { icon: Icon::Folder, name: "Files", linux: false, meta: "app", comment: "Browse and organise your files" },
    Row { icon: Icon::Letter, name: "Fonts", linux: false, meta: "settings", comment: "" },
];
const ACTIONS: &[Row<'static>] = &[
    Row { icon: Icon::Search, name: "Find in files", linux: false, meta: "~/slate", comment: "" },
    Row {
        icon: Icon::Undo,
        name: "Roll back to snapshot \u{201c}factory\u{201d}",
        linux: false,
        meta: "system",
        comment: "",
    },
];

fn render(w: i32, h: i32, scale: f32, draw: impl FnOnce(&mut Painter<'_>, &Fonts<'_>)) -> Canvas {
    let f = fonts();
    let mut canvas = Canvas::new(w, h, Color::rgb(0));
    let mut cache = GlyphCache::new();
    let mut p = Painter::new(&mut canvas, &mut cache, scale);
    draw(&mut p, &f);
    canvas
}

/// Every scene, by name.
fn scenes() -> Vec<(&'static str, Canvas)> {
    let g = Palette::GRAPHITE;
    let sections = [Section { label: "3 matches", rows: APPS }, Section { label: "actions", rows: ACTIONS }];
    let launcher = Launcher { query: "fi", sections: &sections, selected: 0, scroll: None };
    let none = Extras::default();
    let details = [("requested by", "quarry"), ("change", "system image"), ("signature", "verified")];
    let twelve = slate_ui::edit::LineEdit::new("xxxxxxxxxxxx").secret();
    let empty = slate_ui::edit::LineEdit::new("").secret();
    let approval = Approval {
        title: "Approve system update",
        body: "quarry wants to switch to a new signed system image. Your current system is kept as a snapshot, so you can roll back.",
        details: &details,
        user: "alex",
        password: &twelve,
        focus: ApprovalFocus::Password,
        focus_visible: false,
        error: None,
    };
    let mut out = Vec::new();
    out.push(("desktop", render(1440, 900, 1.0, |p, f| desktop(p, &g, f, 0, none))));
    out.push((
        "launcher",
        render(1440, 900, 1.0, |p, f| {
            desktop(p, &g, f, 0, none);
            draw::dim(p, g.dim_launcher, 1.0);
            draw::launcher(p, &g, f, &launcher);
        }),
    ));
    // ADR 0039: the launcher as Strata builds it, with the apps opened last
    // first and the pointer's row (the second) selected; then "trml",
    // found by its letters.
    let entries: Vec<crate::launcher::App> = [
        "name=Terminal\nexec=/bin/terminal\nicon=terminal",
        "name=Shortcuts\nexec=/bin/strata-keys\nicon=letter\nkind=help",
        "name=Settings\nexec=/bin/strata-settings\nicon=sliders\nkind=settings",
        "name=Firefox\nexec=/bin/slate-linux-app firefox\nicon=globe\nlinux=yes",
    ]
    .iter()
    .filter_map(|t| crate::launcher::parse_app(t))
    .collect();
    let recent = ["/bin/strata-settings".to_string(), "/bin/terminal".to_string()].to_vec();
    let mut real = crate::launcher::Launcher::new(entries).with_recent(recent);
    real.hover(1);
    let mut fuzzy = real.clone();
    for c in "trml".chars() {
        fuzzy.key(0, Some(c));
    }
    // ADR 0102: many apps by category, scrolled to the third.
    let mut many: Vec<crate::launcher::App> = Vec::new();
    for (i, (name, cat)) in [
        ("Calculator", "accessories"),
        ("Clock", "accessories"),
        ("Firefox", "internet"),
        ("Mail", "internet"),
        ("Writer", "office"),
        ("Images", "graphics"),
        ("Music", "sound & video"),
        ("Builder", "development"),
        ("Chess", "games"),
        ("Terminal", "system"),
        ("Settings", "settings"),
        ("Shortcuts", "help"),
    ]
    .iter()
    .enumerate()
    {
        many.extend(crate::launcher::parse_app(&alloc::format!("name={name}\nexec=/bin/app{i}\ncategory={cat}")));
    }
    let mut scrolled = crate::launcher::Launcher::new(many);
    for _ in 0..11 {
        scrolled.key(108, None);
    }
    // The live system's launcher (M27): "Install SlateOS" among the actions.
    let mut live = real.clone().with_live(true);
    for c in "inst".chars() {
        live.key(0, Some(c));
    }
    for (name, l) in [
        ("launcher-recent", &real),
        ("launcher-fuzzy", &fuzzy),
        ("launcher-categories", &scrolled),
        ("launcher-live", &live),
    ] {
        out.push((
            name,
            render(1440, 900, 1.0, |p, f| {
                desktop(p, &g, f, 0, none);
                draw::dim(p, g.dim_launcher, 1.0);
                let rows = l.rows();
                let sections = crate::launcher::sections(&rows);
                let (selected, scroll) = l.view();
                let view = Launcher { query: &l.query, sections: &sections, selected, scroll };
                draw::launcher(p, &g, f, &view);
            }),
        ));
    }
    out.push((
        "approval",
        render(1440, 900, 1.0, |p, f| {
            desktop(p, &g, f, 0, none);
            draw::dim(p, g.dim_dialog, 1.0);
            draw::approval(p, &g, f, &approval);
        }),
    ));
    // Full graphics' notice (ADR 0173) as the approval's text: the
    // longest body an approval has.
    let notice = alloc::format!("alex wants to turn on full graphics. {}", slate_display::graphics::NOTICE);
    out.push((
        "approval-graphics",
        render(1440, 900, 1.0, |p, f| {
            desktop(p, &g, f, 0, none);
            let a = Approval { title: slate_display::graphics::TITLE, body: &notice, ..approval.clone() };
            draw::dim(p, g.dim_dialog, 1.0);
            draw::approval(p, &g, f, &a);
        }),
    ));
    out.push((
        "approval-error",
        render(1440, 900, 1.0, |p, f| {
            desktop(p, &g, f, 0, none);
            let a = Approval {
                password: &empty,
                focus: ApprovalFocus::Approve,
                focus_visible: true,
                error: Some("That password didn't work. Try again."),
                ..approval.clone()
            };
            draw::dim(p, g.dim_dialog, 1.0);
            draw::approval(p, &g, f, &a);
        }),
    ));
    out.push(("desktop-linux-focused", render(1440, 900, 1.0, |p, f| desktop(p, &Palette::GRAPHITE, f, 2, none))));
    out.push((
        "desktop-linux-sandbox",
        render(1440, 900, 1.0, |p, f| {
            let (mut wm, ids) = mockup_wm(1440.0, 900.0, 2);
            if let Some(w) = wm.get_mut(ids[2]) {
                w.app = "firefox".into();
                w.sandboxed = true;
            }
            crate::desktop::desktop(p, &g, f, &wm, &status(), none, &mut contents(&g, f, ids));
        }),
    ));
    out.push(("desktop-high-contrast", render(1440, 900, 1.0, |p, f| desktop(p, &Palette::HIGH_CONTRAST, f, 1, none))));
    // The themes in colour (ADR 0167) on their own wallpapers, the
    // terminal focused.
    for (name, theme) in [
        ("desktop-copper-noir", slate_ui::themes::Theme::CopperNoir),
        ("desktop-sediment", slate_ui::themes::Theme::Sediment),
    ] {
        let pal = theme.palette(false);
        let wall = crate::desktop::wallpaper_canvas(&pal, theme.wallpaper(), 1440, 900, 1.0);
        let extras = Extras { wall: Some(&wall), ..none };
        out.push((name, render(1440, 900, 1.0, |p, f| desktop(p, &pal, f, 1, extras))));
    }
    out.push((
        "empty-workspace",
        render(1280, 800, 1.0, |p, f| {
            let (w, h) = p.size();
            let mut wm = Wm::new(w, h);
            wm.apply(Command::Workspace(2));
            let st = Status {
                clock: "Mon 19 Oct  14:32".into(),
                network: Some(false),
                battery: None,
                updates: 0,
                ..Status::default()
            };
            crate::desktop::desktop(p, &g, f, &wm, &st, none, &mut |_, _, _| {});
        }),
    ));
    // Updates waiting (ADR 0112): the top bar says how many.
    out.push((
        "bar-updates",
        render(1280, 800, 1.0, |p, f| {
            let (w, h) = p.size();
            let wm = Wm::new(w, h);
            let st = Status {
                clock: "Mon 19 Oct  14:32".into(),
                network: Some(true),
                battery: None,
                updates: 3,
                ..Status::default()
            };
            crate::desktop::desktop(p, &g, f, &wm, &st, none, &mut |_, _, _| {});
        }),
    ));
    // Floating windows from the window manager: one maximised behind, one
    // normal on top with the pointer over its close button, one minimised
    // (only in the window list).
    out.push((
        "floating",
        render(1280, 800, 1.0, |p, f| {
            let mut wm = Wm::new(1280.0, 800.0);
            let a = wm.add("keys", Some("shortcuts"), false);
            wm.toggle_maximize(a);
            let b = wm.add("terminal", Some("~"), false);
            let c = wm.add("keys", Some("shortcuts"), true);
            wm.minimize(c);
            let st = Status {
                clock: crate::session::clock(&slate_rt::time::gmtime(1_792_400_000)),
                network: Some(true),
                battery: None,
                updates: 0,
                ..Status::default()
            };
            let extras = Extras { hover: Some((b, TitleButton::Close)), ..Extras::default() };
            crate::desktop::desktop(p, &g, f, &wm, &st, extras, &mut |p, _, c| {
                crate::desktop::keys_window(p, &g, f, c)
            });
        }),
    ));
    // ADR 0124's addendum: the keyboard focus on a title bar's maximise
    // button (its ring), and the close button's hover fill half faded in.
    out.push((
        "title-keys",
        render(1280, 800, 1.0, |p, f| {
            let mut wm = Wm::new(1280.0, 800.0);
            let b = wm.add("terminal", Some("~"), false);
            let st = Status {
                clock: crate::session::clock(&slate_rt::time::gmtime(1_792_400_000)),
                network: Some(true),
                battery: None,
                updates: 0,
                ..Status::default()
            };
            let extras = Extras {
                hover: Some((b, TitleButton::Close)),
                hover_in: Some(0.5),
                keyed: Some((b, TitleButton::Maximize)),
                ..Extras::default()
            };
            crate::desktop::desktop(p, &g, f, &wm, &st, extras, &mut |p, _, c| {
                crate::desktop::keys_window(p, &g, f, c)
            });
        }),
    ));
    // ADR 0102's third addendum: icons on the desktop (one selected, a
    // long name in two lines), and a terminal resized in its cells.
    // ADR 0156: the desktop with the keys (a ring on the icon they are
    // on), a rename refused, and the wallpaper's menu.
    out.push((
        "desk-rename-and-menu",
        render(1280, 800, 1.0, |p, f| {
            use crate::desk::{Action, Desk, Item, Kind, Menu};
            use slate_ui::fileicon::Kind as FileKind;
            use slate_ui::icon::Icon;
            let mut desk = Desk::default();
            desk.screen = (1280.0, 800.0);
            let item = |name: &str, kind: Kind| Item {
                name: String::from(name),
                path: alloc::format!("/d/{name}"),
                kind,
                icon: Icon::Document,
            };
            desk.set(alloc::vec![
                item("Projects", Kind::Folder),
                item("plans.txt", Kind::File(FileKind::Text)),
                item("taken.txt", Kind::File(FileKind::Text)),
            ]);
            desk.cursor = Some(0);
            desk.start_rename(1);
            if let Some((_, e, why)) = desk.rename.as_mut() {
                e.select_all();
                e.insert("taken.txt");
                *why = Some(String::from("There's already something called taken.txt here."));
            }
            desk.menu = Some(Menu {
                x: 600.0,
                y: 300.0,
                items: alloc::vec![
                    ("New Folder", Action::NewFolder),
                    ("Show the Desktop in Files", Action::ShowInFiles),
                    ("Change Wallpaper", Action::Wallpaper),
                ],
                selected: 1,
            });
            let wm = Wm::new(1280.0, 800.0);
            let extras = Extras { desk: Some(&desk), desk_keys: true, ..Extras::default() };
            crate::desktop::desktop(p, &g, f, &wm, &status(), extras, &mut |_, _, _| {});
        }),
    ));
    // Two icons dragged towards a free place over a window, the icon
    // menu's Move to Trash, more icons than cells, and an app's drag.
    out.push((
        "desk-dragging",
        render(1280, 800, 1.0, |p, f| {
            use crate::desk::{Action, Desk, Item, Kind, Menu, Press};
            use slate_ui::fileicon::Kind as FileKind;
            use slate_ui::icon::Icon;
            let mut desk = Desk::default();
            desk.screen = (1280.0, 800.0);
            let mut items = alloc::vec![Item {
                name: String::from("Projects"),
                path: String::from("/d/Projects"),
                kind: Kind::Folder,
                icon: Icon::Folder,
            }];
            items.extend((1..100).map(|n| Item {
                name: alloc::format!("photo {n:02}.png"),
                path: alloc::format!("/d/photo {n:02}.png"),
                kind: Kind::File(FileKind::Picture),
                icon: Icon::Document,
            }));
            desk.set(items);
            desk.selected = alloc::vec![1, 2];
            desk.press =
                Some(Press::Icon { i: 1, x0: 60.0, y0: 170.0, x: 460.0, y: 300.0, dragging: true, mods: false });
            desk.menu = Some(Menu {
                x: 900.0,
                y: 500.0,
                items: alloc::vec![
                    ("Open", Action::Open),
                    ("Rename", Action::Rename),
                    ("Move to Trash", Action::Trash)
                ],
                selected: 0,
            });
            let mut wm = Wm::new(1280.0, 800.0);
            let t = wm.add("files", Some("~/Pictures"), false);
            if let Some(w) = wm.get_mut(t) {
                w.rect = Area::new(700.0, 120.0, 520.0, 360.0);
            }
            let extras = Extras { desk: Some(&desk), drag_badge: Some((1000.0, 640.0, 3, false)), ..Extras::default() };
            crate::desktop::desktop(p, &g, f, &wm, &status(), extras, &mut |p, _, c| {
                crate::desktop::keys_window(p, &g, f, c)
            });
        }),
    ));
    for (name, g) in [("desk-icons-and-steps", g), ("desk-icons-light", Palette::DAY)] {
        out.push((
            name,
            render(1280, 800, 1.0, |p, f| {
                use crate::desk::{Desk, Item, Kind};
                use slate_ui::fileicon::Kind as FileKind;
                use slate_ui::icon::Icon;
                let mut desk = Desk::default();
                let item = |name: &str, kind: Kind, icon: Icon| Item {
                    name: String::from(name),
                    path: String::new(),
                    kind,
                    icon,
                };
                desk.set(alloc::vec![
                    item("Projects", Kind::Folder, Icon::Folder),
                    item("holiday photos from the coast.png", Kind::File(FileKind::Picture), Icon::Document),
                    item("photos.zip", Kind::File(FileKind::Archive), Icon::Document),
                    item("Files", Kind::App(String::from("/bin/files")), Icon::Folder),
                    item("build.sh", Kind::File(FileKind::Program), Icon::Document),
                    item("Calculator", Kind::App(String::from("/bin/calculator")), Icon::Calculator),
                    item("notes.txt", Kind::File(FileKind::Text), Icon::Document),
                ]);
                desk.selected = alloc::vec![2];
                let mut wm = Wm::new(1280.0, 800.0);
                let t = wm.add("terminal", Some("~"), false);
                if let Some(w) = wm.get_mut(t) {
                    w.rect = Area::new(420.0, 160.0, 640.0, 440.0);
                }
                wm.steps(t, (32.0, 24.0), (7.8, 21.0));
                let st = Status {
                    clock: crate::session::clock(&slate_rt::time::gmtime(1_792_400_000)),
                    network: Some(true),
                    battery: None,
                    updates: 0,
                    ..Status::default()
                };
                let extras = Extras { desk: Some(&desk), resizing: Some(t), ..Extras::default() };
                crate::desktop::desktop(p, &g, f, &wm, &st, extras, &mut |p, _, c| {
                    crate::desktop::keys_window(p, &g, f, c)
                });
            }),
        ));
    }
    // ADR 0039: a window dragged to the left edge (the half it would snap
    // to outlined), a crowded window list scrolled by two, light contents
    // that show the rounded bottom corners, and the resize cursor on a
    // window's right edge.
    out.push((
        "snap-and-list",
        render(1280, 800, 1.0, |p, f| {
            let mut wm = Wm::new(1280.0, 800.0);
            for i in 0..11 {
                let name = ["terminal", "keys", "files", "editor"][i % 4];
                wm.add(name, Some("~"), i % 5 == 3);
            }
            let top = wm.add("terminal", Some("~/slate"), false);
            if let Some(w) = wm.get_mut(top) {
                w.rect = Area::new(200.0, 150.0, 560.0, 380.0);
            }
            let st = Status {
                clock: crate::session::clock(&slate_rt::time::gmtime(1_792_400_000)),
                network: Some(true),
                battery: None,
                updates: 0,
                ..Status::default()
            };
            let extras =
                Extras { preview: Some(wm.snap_area(crate::wm::State::Left)), list_first: 2, ..Extras::default() };
            crate::desktop::desktop(p, &g, f, &wm, &st, extras, &mut |p, _, c| {
                p.fill(c, 0.0, g.text_3);
            });
            slate_ui::icon::cursor(p.canvas, 760.0, 340.0, 1.0, slate_ui::icon::Cursor::ResizeH);
        }),
    ));
    // ADR 0102: windows in three quarters, the fourth's preview.
    out.push((
        "snap-quarters",
        render(1280, 800, 1.0, |p, f| {
            let mut wm = Wm::new(1280.0, 800.0);
            for (name, state) in [
                ("terminal", crate::wm::State::TopLeft),
                ("keys", crate::wm::State::TopRight),
                ("settings", crate::wm::State::BottomLeft),
            ] {
                let id = wm.add(name, Some("~"), false);
                wm.snap(id, state);
            }
            let st = Status {
                clock: crate::session::clock(&slate_rt::time::gmtime(1_792_400_000)),
                network: Some(true),
                battery: None,
                updates: 0,
                ..Status::default()
            };
            let extras = Extras { preview: Some(wm.snap_area(crate::wm::State::BottomRight)), ..Extras::default() };
            crate::desktop::desktop(p, &g, f, &wm, &st, extras, &mut |p, _, c| {
                p.fill(c, 0.0, g.text_3);
            });
        }),
    ));
    // A switch from workspace 1 to 2, frozen half-way (ADR 0039).
    out.push((
        "workspace-slide",
        render(1280, 800, 1.0, |p, f| {
            let mut wm = Wm::new(1280.0, 800.0);
            wm.add("keys", Some("shortcuts"), false);
            wm.apply(Command::Workspace(1));
            wm.add("terminal", Some("~"), false);
            let st = Status {
                clock: crate::session::clock(&slate_rt::time::gmtime(1_792_400_000)),
                network: Some(true),
                battery: None,
                updates: 0,
                ..Status::default()
            };
            let slide = Some(crate::motion::Slide { from: 0, shift: 640.0, dir: 1.0 });
            let extras = Extras { slide, ..Extras::default() };
            crate::desktop::desktop(p, &g, f, &wm, &st, extras, &mut |p, _, c| {
                crate::desktop::keys_window(p, &g, f, c)
            });
        }),
    ));
    // Motion, frozen half-way: the terminal fading in over a window whose
    // border is cross-fading, and the launcher appearing.
    out.push((
        "motion",
        render(1280, 800, 1.0, |p, f| {
            let mut wm = Wm::new(1280.0, 800.0);
            let a = wm.add("keys", Some("shortcuts"), false);
            let b = wm.add("terminal", Some("~"), false);
            let look = move |id: WinId| {
                if id == b {
                    crate::motion::Look { focus: 0.5, opacity: 0.5, dy: -3.0 }
                } else {
                    crate::motion::Look { focus: if id == a { 0.5 } else { 0.0 }, opacity: 1.0, dy: 0.0 }
                }
            };
            let st = Status {
                clock: crate::session::clock(&slate_rt::time::gmtime(1_792_400_000)),
                network: Some(true),
                battery: None,
                updates: 0,
                ..Status::default()
            };
            let extras = Extras { look: Some(&look), ..Extras::default() };
            crate::desktop::desktop(p, &g, f, &wm, &st, extras, &mut |p, _, c| {
                crate::desktop::keys_window(p, &g, f, c)
            });
            draw::dim(p, g.dim_launcher, 0.5);
            let mut layer = Canvas::new(1280, 800, Color::TRANSPARENT);
            let mut cache = GlyphCache::new();
            let mut lp = Painter::new(&mut layer, &mut cache, 1.0);
            draw::launcher(&mut lp, &g, f, &launcher);
            p.canvas.composite(&layer, 0.5, 3);
        }),
    ));
    // The Applications menu (ADR 0110), under its button, drawn on a layer
    // and composited as Strata draws it, with the image's own app entries.
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../rootfs/usr/share/strata/apps");
    let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
    entries.sort();
    let real_apps: Vec<crate::launcher::App> =
        entries.iter().filter_map(|p| crate::launcher::parse_app(&std::fs::read_to_string(p).unwrap())).collect();
    let recent = std::vec!["/bin/files".to_string(), "/bin/terminal".to_string(), "/bin/calendar".to_string()];
    let mut opened = crate::menu::Menu::new(real_apps.clone(), recent.clone());
    let mut accessories = crate::menu::Menu::new(real_apps.clone(), recent);
    accessories.hover_category(2);
    accessories.hover_app(3);
    let mut search = crate::menu::Menu::new(real_apps.clone(), Vec::new());
    for c in "cal".chars() {
        search.key(0, Some(c));
    }
    opened.pane = crate::menu::Pane::Categories;
    for (name, m, pal) in [
        ("applications-menu", &opened, g),
        ("applications-menu-accessories", &accessories, g),
        ("applications-menu-search", &search, g),
        ("applications-menu-light", &accessories, Palette::DAY),
    ] {
        out.push((
            name,
            render(1280, 800, 1.0, |p, f| {
                let mut wm = Wm::new(1280.0, 800.0);
                wm.add("keys", Some("shortcuts"), false);
                let st = Status {
                    clock: crate::session::clock(&slate_rt::time::gmtime(1_792_400_000)),
                    network: Some(true),
                    battery: None,
                    updates: 0,
                    ..Status::default()
                };
                let ex = Extras { menu: true, ..Extras::default() };
                crate::desktop::desktop(p, &pal, f, &wm, &st, ex, &mut |p, _, c| {
                    crate::desktop::keys_window(p, &pal, f, c)
                });
                let mut layer = Canvas::new(1280, 800, Color::TRANSPARENT);
                let mut cache = GlyphCache::new();
                let mut lp = Painter::new(&mut layer, &mut cache, 1.0);
                draw::apps_menu(&mut lp, &pal, f, m);
                p.canvas.composite(&layer, 1.0, 0);
            }),
        ));
    }
    // The live system's desktop (M27): the panel's "Install SlateOS".
    out.push((
        "desktop-live",
        render(1280, 800, 1.0, |p, f| {
            let wm = Wm::new(1280.0, 800.0);
            let st = Status {
                clock: crate::session::clock(&slate_rt::time::gmtime(1_792_400_000)),
                network: Some(true),
                battery: None,
                updates: 0,
                ..Status::default()
            };
            let ex = Extras { live: true, ..Extras::default() };
            let hits = crate::desktop::desktop(p, &g, f, &wm, &st, ex, &mut |_, _, _| {});
            assert!(hits.install.is_some_and(|a| a.y == 4.0 && a.right() < 1280.0 - 200.0));
        }),
    ));
    // The power dialog (ADR 0110): from the power button, keys used, and
    // after a failure; later and the updates first, what is set for later,
    // and its other face (ADR 0110's addendum).
    use crate::power::{Pending, Power, Row, Why};
    let error = Power {
        error: Some("Restart didn't work: not allowed by the policy".into()),
        ..Power::new(draw::PowerChoice::Restart)
    };
    let keys = Power { focus_visible: true, ..Power::new(draw::PowerChoice::Lock) };
    let later = Power {
        focus_visible: true,
        row: Row::Options,
        when: 2,
        at: 4,
        install: true,
        ..Power::new(draw::PowerChoice::Restart).with_updates(3)
    };
    let set = Pending::at(draw::PowerChoice::ShutDown, "21:45", true, 30 * 60_000, 0);
    let pending = Power::new(draw::PowerChoice::ShutDown).with_pending(Some(set.clone()));
    let unsaved = Power::asking(
        draw::PowerChoice::ShutDown,
        Why::Unsaved,
        ["Text Editor · ~/notes/plans.txt", "Calendar", "Contacts", "Text Editor · ~/todo.md", "Images", "Files"]
            .map(String::from)
            .to_vec(),
    );
    let one = Power {
        focus_visible: true,
        ..Power::asking(draw::PowerChoice::LogOut, Why::Unsaved, std::vec!["Text Editor · notes.txt".into()])
    };
    let not_installed = Power::asking(draw::PowerChoice::Restart, Why::NotInstalled, Vec::new());
    for (name, pal, power, top) in [
        ("power-dialog", g, &Power::new(draw::PowerChoice::ShutDown), None),
        ("power-dialog-keys-light", Palette::DAY, &keys, None),
        ("power-dialog-error", g, &error, None),
        ("power-dialog-later", g, &later, None),
        ("power-dialog-later-light", Palette::DAY, &later, None),
        ("power-dialog-pending", g, &pending, Some(set.text())),
        ("power-dialog-unsaved", g, &unsaved, None),
        ("power-dialog-unsaved-one-light", Palette::DAY, &one, None),
        ("power-dialog-not-installed", g, &not_installed, None),
    ] {
        out.push((
            name,
            render(1280, 800, 1.0, |p, f| {
                let mut wm = Wm::new(1280.0, 800.0);
                wm.add("keys", Some("shortcuts"), false);
                let st = Status {
                    clock: crate::session::clock(&slate_rt::time::gmtime(1_792_400_000)),
                    network: Some(true),
                    battery: Some(62),
                    updates: power.updates,
                    ..Status::default()
                };
                let ex = Extras { power: true, pending: top.as_deref(), ..Extras::default() };
                crate::desktop::desktop(p, &pal, f, &wm, &st, ex, &mut |p, _, c| {
                    crate::desktop::keys_window(p, &pal, f, c)
                });
                draw::dim(p, pal.dim_dialog, 1.0);
                let v = draw::PowerView { name: "Ada Lovelace", user: "ada", power };
                draw::power_dialog(p, &pal, f, &v);
            }),
        ));
    }
    // The top bar with a shut down set for later, in its last minute.
    out.push((
        "desktop-pending",
        render(1280, 800, 1.0, |p, f| {
            let mut wm = Wm::new(1280.0, 800.0);
            wm.add("keys", Some("shortcuts"), false);
            let st = Status {
                clock: crate::session::clock(&slate_rt::time::gmtime(1_792_400_000)),
                network: Some(true),
                battery: None,
                updates: 2,
                ..Status::default()
            };
            let text = Pending::at(draw::PowerChoice::Restart, "21:45", false, 42_000, 0).text();
            let ex = Extras { pending: Some(&text), ..Extras::default() };
            let hits = crate::desktop::desktop(p, &g, f, &wm, &st, ex, &mut |p, _, c| {
                crate::desktop::keys_window(p, &g, f, c)
            });
            let (a, u) = (hits.pending.unwrap(), hits.updates.unwrap());
            assert!(a.right() < u.x && a.y == u.y, "left of the updates: {a:?} {u:?}");
        }),
    ));
    // The login screen (ADR 0038).
    let people = crate::greeter::people(
        "root:x:0:0:root:/root:/bin/sh\ngreeter:x:65:65::/:/bin/nologin\nada:x:1000:1000:Ada Lovelace,,,:/home/ada:/bin/sh\n\
         alex:x:1001:1001::/home/alex:/bin/sh\n",
    );
    let asking = crate::greeter::Status::Asking;
    let refused = crate::greeter::Status::Refused("That password didn't work. Try again.".into());
    let no_name = slate_ui::edit::LineEdit::new("");
    let seven = slate_ui::edit::LineEdit::new("xxxxxxx").secret();
    let none_typed = slate_ui::edit::LineEdit::new("").secret();
    let grace = slate_ui::edit::LineEdit::new("grace");
    // The caret moved back three, two chosen (ADR 0101's line editor).
    let mut moved = seven.clone();
    moved.place(4, false);
    moved.place(2, true);
    let base = crate::greeter::View {
        host: "workstation",
        people: &people,
        selected: 0,
        first: 0,
        name: &no_name,
        focus: crate::greeter::Focus::Password,
        password: &seven,
        status: &asking,
        time: "08:53",
        date: "monday · 19 october",
        confirm: None,
        change: None,
    };
    let crowd = crate::greeter::people(
        &(1..=8).map(|i| format!("user{i}:x:{}:100:Person {i}:/home/u{i}:/bin/sh\n", 1000 + i)).collect::<String>(),
    );
    let views = [
        ("login", base, false),
        ("login-refused", crate::greeter::View { password: &none_typed, status: &refused, ..base }, false),
        ("login-caret", crate::greeter::View { password: &moved, ..base }, false),
        (
            "login-someone-else",
            crate::greeter::View {
                selected: 2,
                name: &grace,
                focus: crate::greeter::Focus::Name,
                password: &none_typed,
                ..base
            },
            false,
        ),
        ("login-long-list", crate::greeter::View { people: &crowd, selected: 6, first: 2, ..base }, false),
        ("login-confirm", crate::greeter::View { confirm: Some(crate::greeter::Confirm::PowerOff), ..base }, false),
        ("login-high-contrast", base, true),
        // The password was right but has expired (ADR 0143).
        (
            "login-expired",
            crate::greeter::View {
                password: &none_typed,
                focus: crate::greeter::Focus::Confirm,
                change: Some((&seven, &none_typed)),
                ..base
            },
            false,
        ),
    ];
    for (name, v, contrast) in views {
        let pal = if contrast { Palette::HIGH_CONTRAST } else { g };
        out.push((name, render(1440, 900, 1.0, |p, f| drop(crate::greeter::draw(p, &pal, f, &v)))));
    }
    // One person at 1280 × 800, as the graphical scenario sees it (it looks
    // inside the password field, at 300, 560).
    let one = &base.people[..1];
    let alone = crate::greeter::View { people: one, password: &none_typed, ..base };
    out.push(("login-one", render(1280, 800, 1.0, |p, f| drop(crate::greeter::draw(p, &g, f, &alone)))));
    // The lock screen (ADR 0039).
    use crate::lock::{Focus, Status as LockStatus};
    for (name, status, len, focus) in [
        ("lock", LockStatus::Asking, 5, Focus::Password),
        ("lock-wrong", LockStatus::Wrong, 0, Focus::Password),
        // "Switch person" chosen, asking to confirm (ADR 0102).
        ("lock-switch", LockStatus::Asking, 0, Focus::Confirm),
    ] {
        let mut l = crate::lock::Lock::default();
        l.password.set_text(&"x".repeat(len));
        (l.status, l.focus) = (status, focus);
        out.push((
            name,
            render(1440, 900, 1.0, |p, f| {
                let screen = crate::lock::Screen {
                    name: "Ada Lovelace",
                    user: "ada",
                    time: "14:32",
                    date: "sunday · 25 october",
                    host: "workstation",
                    network: Some(true),
                    battery: Some(84),
                    wall: None,
                    face: None,
                    now: 0,
                    reduced_motion: false,
                };
                crate::lock::draw(p, &g, f, &screen, &l);
            }),
        ));
    }
    // The light variant at 1280 × 800, positions and the clock scaled.
    out.push((
        "lock-light",
        render(1280, 800, 1.0, |p, f| {
            let screen = crate::lock::Screen {
                name: "Ada Lovelace",
                user: "ada",
                time: "09:05",
                date: "monday · 19 october",
                host: "workstation",
                network: Some(true),
                battery: None,
                wall: None,
                face: None,
                now: 0,
                reduced_motion: false,
            };
            crate::lock::draw(p, &Palette::DAY, f, &screen, &crate::lock::Lock::default());
        }),
    ));
    // A person's picture (ADR 0110's second addendum): on the lock screen
    // and the login screen's list.
    let photo = slate_image::decode(include_bytes!("../../../libs/image/tests/fixtures/photo420.jpg")).unwrap();
    let face = crate::faces::cover(&photo, crate::faces::SIDE, crate::faces::SIDE);
    out.push((
        "lock-face",
        render(1280, 800, 1.0, |p, f| {
            let screen = crate::lock::Screen {
                name: "Ada Lovelace",
                user: "ada",
                time: "09:05",
                date: "monday · 19 october",
                host: "workstation",
                network: Some(true),
                battery: None,
                wall: None,
                face: Some(&face),
                now: 0,
                reduced_motion: false,
            };
            crate::lock::draw(p, &g, f, &screen, &crate::lock::Lock::default());
        }),
    ));
    let mut pictured = people.clone();
    pictured[0].face = Some(face.clone());
    let with_faces = crate::greeter::View { people: &pictured, ..base };
    out.push(("login-faces", render(1280, 800, 1.0, |p, f| drop(crate::greeter::draw(p, &g, f, &with_faces)))));
    // The Settings app (ADR 0039): its switches, and the time zone list
    // filtered by "euro" (2026-10-19 08:53 UTC, so Europe is on summer
    // time).
    let zones: &[u8] = include_bytes!("../../../rootfs/usr/share/slate/zones");
    let names = slate_rt::tz::names(zones);
    let at = crate::settings_app::Zones { names: &names, table: Some(zones), now: 1_792_400_000 };
    use crate::settings_app::{Account, Focus as SFocus, Page, Section as S, Security, View};
    let settings =
        crate::settings::Settings { dim: true, wallpaper: slate_ui::wallpaper::Design::Dunes, ..Default::default() };
    let mut base = View::new(settings, "Europe/London");
    base.accounts = std::vec![
        Account { name: "ada".into(), full: "Ada Lovelace".into(), admin: true, uid: 1000 },
        Account { name: "grace".into(), full: "Grace Hopper".into(), admin: false, uid: 1001 },
    ];
    base.me = "ada".into();
    base.security = Security {
        compat: Some(true),
        devmode: false,
        encrypted: true,
        firewall: Some(true),
        ports: std::vec![(true, 22), (false, 5353)],
    };
    base.about = [
        ("release", "Slate 0.28"),
        ("kernel", "Slate 0.1.0 (Linux 6.12 interface)"),
        ("computer name", "workstation"),
        ("processor", "AMD Ryzen 9 7950X 16-Core Processor × 32"),
        ("memory", "125 GiB"),
        ("disk nvme0n1", "WDS500G1X0E-00AFY0, 465.8 GiB"),
        ("up for", "2 hours, 14 minutes"),
        ("desktop", "Strata"),
    ]
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .to_vec();
    base.focus_visible = true;
    // Two displays (ADR 0170): a 1440p one at 144 Hz, primary, and a
    // 1080p one on its right.
    base.displays = crate::displays::Now::parse(
        "scale 1 auto\n\
         DP-1 lit 0,0 2560x1440@144 primary modes 2560x1440@144 2560x1440@60 1920x1080@60\n\
         HDMI-A-1 lit 2560,0 1920x1080@60 modes 1920x1080@60 1280x720@60\n",
    );
    let at_section = |s: S, focus: SFocus, row: usize| {
        let mut v = base.clone();
        v.open_section(crate::settings_app::SECTIONS.iter().position(|x| *x == s).unwrap());
        (v.focus, v.row) = (focus, row);
        v
    };
    let with_page = |s: S, page: Page| {
        let mut v = at_section(s, SFocus::Content, 0);
        v.page = page;
        v
    };
    let mut add = with_page(
        S::Users,
        Page::Add {
            fields: alloc::boxed::Box::new([
                slate_ui::edit::LineEdit::new("Grace Hopper"),
                slate_ui::edit::LineEdit::new("grace"),
                slate_ui::edit::LineEdit::new("secret").secret(),
                slate_ui::edit::LineEdit::new("secre").secret(),
            ]),
            admin: true,
            focus: 3,
            error: Some((3, "The two passwords are not the same".into())),
            typed_login: false,
        },
    );
    add.accounts.truncate(1);
    let mut removing = with_page(S::Users, Page::Account { name: "grace".into() });
    removing.row = 2;
    removing.say("Press Enter again to remove the account and its files.", true);
    // Bluetooth (ADR 0113): a keyboard paired, a phone and headphones
    // nearby; then the phone's pairing question, and a passkey.
    let mut bt = at_section(S::Bluetooth, SFocus::Content, 2);
    bt.bluetooth = Some(slate_bluetooth::proto::parse_snapshot(
        "state on\ncontroller C0:FF:EE:00:00:01 workstation\ndiscovering yes\nvisible yes\n\
         device 00:1F:20:44:55:66 paired near keyboard Slate Keyboard\n\
         device 5C:F3:70:11:22:33 found near phone Ada's Phone\n\
         device 11:22:33:44:55:66 found near headphones Studio Headphones\n",
    ));
    let mut bt_pairing = bt.clone();
    if let Some(b) = bt_pairing.bluetooth.as_mut() {
        b.discovering = false;
        b.busy = Some(b.devices[1].addr);
        b.prompt = Some(slate_bluetooth::host::Prompt::Confirm(b.devices[1].addr, 482_913));
    }
    let mut bt_passkey = bt.clone();
    if let Some(b) = bt_passkey.bluetooth.as_mut() {
        b.devices[0].paired = false;
        b.busy = Some(b.devices[0].addr);
        b.prompt = Some(slate_bluetooth::host::Prompt::Passkey(b.devices[0].addr, 7_351));
    }
    // Pictures: the wallpaper's own (chosen), the accounts', one's own
    // account page, and a full name being typed.
    let mut own_picture = at_section(S::Appearance, SFocus::Content, 2 + slate_ui::wallpaper::Design::ALL.len());
    own_picture.settings.picture = true;
    own_picture.picture = Some(crate::faces::cover(&photo, 320, 200));
    let mut users_faces = at_section(S::Users, SFocus::Content, 0);
    users_faces.faces = std::vec![(String::from("ada"), face.clone())];
    let mut own_account = users_faces.clone();
    own_account.open_section(crate::settings_app::SECTIONS.iter().position(|x| *x == S::Users).unwrap());
    own_account.focus = SFocus::Content;
    own_account.key(slate_display::input::KEY_ENTER, None, 0, &[]);
    own_account.key(slate_display::input::KEY_DOWN, None, 0, &[]);
    let mut naming = own_account.clone();
    naming.key(slate_display::input::KEY_ENTER, None, 0, &[]);
    for c in " King".chars() {
        naming.key(0, Some(c), 0, &[]);
    }
    let pages = [
        ("settings", at_section(S::Appearance, SFocus::Content, 3)),
        ("settings-own-picture", own_picture),
        ("settings-users-faces", users_faces),
        ("settings-own-account", own_account),
        ("settings-full-name", naming),
        ("settings-accessibility", at_section(S::Accessibility, SFocus::Content, 1)),
        ("settings-displays", at_section(S::Displays, SFocus::Content, 1)),
        // A machine with an AMD card (ADR 0173): full graphics chosen, for
        // the next start.
        ("settings-graphics", {
            let mut v = at_section(S::Displays, SFocus::Content, 3);
            v.graphics = Some(crate::settings_app::Graphics { installed: true, available: true, running: false });
            v
        }),
        ("settings-display", {
            let mut v = with_page(S::Displays, Page::Display { name: "HDMI-A-1".into() });
            v.row = 2;
            v
        }),
        (
            "settings-zones",
            with_page(S::DateTime, Page::Zones { query: slate_ui::edit::LineEdit::new("euro"), selected: 3, first: 0 }),
        ),
        (
            "settings-network",
            with_page(
                S::Network,
                Page::Network {
                    card: "*".into(),
                    same: false,
                    fixed: true,
                    fields: alloc::boxed::Box::new(
                        ["192.168.1.20/24", "192.168.1", "9.9.9.9 1.1.1.1"].map(slate_ui::edit::LineEdit::new),
                    ),
                    focus: 2,
                    errors: slate_netconf::FieldErrors {
                        gateway: Some("Like 192.168.1.1, or empty."),
                        ..Default::default()
                    },
                },
            ),
        ),
        (
            "settings-network-auto",
            with_page(
                S::Network,
                Page::Network {
                    card: "eth1".into(),
                    same: true,
                    fixed: false,
                    fields: Default::default(),
                    focus: 0,
                    errors: Default::default(),
                },
            ),
        ),
        ("settings-pictures", {
            // The chooser for one's own picture: no picture, those found,
            // typing a path; the second picture chosen.
            let mut v = at_section(S::Users, SFocus::Content, 0);
            v.pictures = std::vec![
                "/home/ada/Pictures/harbour.jpg".into(),
                "/home/ada/Pictures/me.png".into(),
                "/home/ada/Pictures/2026/garden.png".into(),
                "/home/ada/Desktop/scan.bmp".into(),
            ];
            v.home = "/home/ada".into();
            v.open_pick(crate::settings_app::Entry::Face("ada".into()));
            if let Page::Pick { selected, .. } = &mut v.page {
                *selected = 2;
            }
            v
        }),
        ("settings-network-cards", {
            // Every card automatic; eth1 with an address of its own.
            let mut v = at_section(S::Network, SFocus::Content, 2);
            v.cards = std::vec!["eth0".into(), "eth1".into()];
            v.named = std::vec![
                slate_netconf::Card::from_words(&["eth1", "static", "10.0.0.2/24", "gateway", "10.0.0.1"]).unwrap()
            ];
            v
        }),
        ("settings-users", at_section(S::Users, SFocus::Content, 1)),
        ("settings-add-account", add),
        ("settings-account", removing),
        ("settings-bluetooth", bt),
        ("settings-bluetooth-pairing", bt_pairing),
        ("settings-bluetooth-passkey", bt_passkey),
        ("settings-security", at_section(S::Security, SFocus::Content, 0)),
        ("settings-session", at_section(S::Session, SFocus::Sidebar, 0)),
        ("settings-about", at_section(S::About, SFocus::Sidebar, 0)),
    ];
    for (name, v) in &pages {
        out.push((
            name,
            render(900, 660, 1.0, |p, f| {
                p.fill(Area::new(0.0, 0.0, 900.0, 660.0), 0.0, g.window);
                crate::settings_app::draw(p, &g, f, Area::new(0.0, 0.0, 900.0, 660.0), v, at);
            }),
        ));
    }
    // Appearance in the light variant.
    let mut light_page = at_section(S::Appearance, SFocus::Sidebar, 0);
    light_page.settings.theme = slate_ui::themes::Theme::Light;
    light_page.settings.wallpaper = slate_ui::wallpaper::Design::Strata;
    out.push((
        "settings-light",
        render(900, 660, 1.0, |p, f| {
            p.fill(Area::new(0.0, 0.0, 900.0, 660.0), 0.0, Palette::DAY.window);
            crate::settings_app::draw(p, &Palette::DAY, f, Area::new(0.0, 0.0, 900.0, 660.0), &light_page, at);
        }),
    ));
    // The light variant (WM_STYLE §9) with unfocused windows dimmed (§4):
    // Settings focused beside the shortcuts.
    let day = Palette::DAY;
    let light = crate::settings_app::View::new(
        crate::settings::Settings { theme: slate_ui::themes::Theme::Light, dim: true, ..Default::default() },
        "Europe/London",
    );
    out.push((
        "light-dimmed",
        render(1280, 800, 1.0, |p, f| {
            let mut wm = Wm::new(1280.0, 800.0);
            let keys = wm.add("keys", Some("shortcuts"), false);
            let set = wm.add("settings", None, false);
            wm.get_mut(keys).unwrap().rect = Area::new(10.0, 42.0, 600.0, 520.0);
            wm.get_mut(set).unwrap().rect = Area::new(620.0, 42.0, 650.0, 640.0);
            wm.focus(set);
            let st = Status {
                clock: crate::session::clock(&slate_rt::time::gmtime(1_792_400_000)),
                network: Some(true),
                battery: Some(84),
                updates: 0,
                ..Status::default()
            };
            let extras = Extras { dim: true, ..Extras::default() };
            crate::desktop::desktop(p, &day, f, &wm, &st, extras, &mut |p, id, c| {
                if id == keys {
                    crate::desktop::keys_window(p, &day, f, c);
                } else {
                    crate::settings_app::draw(p, &day, f, c, &light, at);
                }
            });
        }),
    ));
    // The icons of the menu, the power dialog and Settings (ADR 0110), at
    // the sizes they are drawn.
    {
        use slate_ui::icon::Icon;
        let icons = [
            Icon::Grid,
            Icon::Briefcase,
            Icon::Code,
            Icon::Play,
            Icon::Lock,
            Icon::LogOut,
            Icon::Restart,
            Icon::Power,
            Icon::People,
            Icon::Picture,
            Icon::Accessibility,
            Icon::LeftRight,
        ];
        out.push((
            "icons",
            render(icons.len() as i32 * 56 + 16, 104, 1.0, |p, _| {
                p.fill(Area::new(0.0, 0.0, icons.len() as f32 * 56.0 + 16.0, 104.0), 0.0, g.window);
                for (i, ic) in icons.iter().enumerate() {
                    let x = 16.0 + i as f32 * 56.0;
                    p.icon(*ic, x, 16.0, 40.0, g.text_1);
                    p.icon(*ic, x + 12.0, 68.0, 16.0, g.text_3);
                }
            }),
        ));
    }
    // The built-in wallpapers (ADR 0110), graphite and light.
    for d in slate_ui::wallpaper::Design::ALL {
        for (pal, light) in [(g, ""), (day, "-light")] {
            let name: &'static str = std::boxed::Box::leak(format!("wallpaper-{}{light}", d.key()).into_boxed_str());
            out.push((
                name,
                render(1280, 800, 1.0, |p, _| {
                    slate_ui::wallpaper::draw(p, &pal, Area::new(0.0, 0.0, 1280.0, 800.0), d)
                }),
            ));
        }
    }
    out
}

#[test]
fn desktop_entries() {
    let firefox = crate::launcher::parse_desktop_entry(
        "[Desktop Entry]\nName=Firefox\nExec=firefox %u\nType=Application\nCategories=Network;WebBrowser;\n\
         [Desktop Action new-window]\nName=New Window\nExec=firefox --new-window %u\n",
    )
    .unwrap();
    assert_eq!(
        (firefox.name.as_str(), firefox.exec.as_str(), firefox.linux),
        ("Firefox", "/bin/slate-linux-app firefox", true)
    );
    assert!(crate::launcher::parse_desktop_entry("[Desktop Entry]\nName=X\nExec=x\nNoDisplay=true\n").is_none());
    assert!(crate::launcher::parse_desktop_entry("[Desktop Entry]\nName=T\nExec=t\nTerminal=true\n").is_none());
}

#[test]
fn people_who_can_log_in() {
    let p = crate::greeter::people(
        "root:x:0:0::/root:/bin/sh\nada:x:1000:1000:Ada L,1:/home/ada:/bin/sh\nsvc:x:1002:1002::/:/bin/nologin\n\
         bo:x:1003:1003::/home/bo:/bin/sh\nnobody:x:65534:65534::/:/bin/sh\n",
    );
    let names: Vec<(&str, &str)> = p.iter().map(|x| (x.name.as_str(), x.full_name.as_str())).collect();
    assert_eq!(names, [("ada", "Ada L"), ("bo", "bo")]);
}

#[test]
fn clock_format() {
    assert_eq!(crate::session::clock(&slate_rt::time::gmtime(1_792_400_000)), "Mon 19 Oct  08:53");
}

fn fingerprint(c: &Canvas) -> u64 {
    c.pixels
        .iter()
        .flat_map(|p| p.to_le_bytes())
        .fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3))
}

/// The scenes look as they did when last reviewed.
#[test]
fn scenes_match_references() {
    let all = scenes();
    if let Ok(dir) = std::env::var("SLATE_UI_OUT") {
        for (name, c) in &all {
            std::fs::write(format!("{dir}/strata-{name}.png"), slate_ui::png::encode(c)).unwrap();
        }
    }
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/screens.txt");
    let got: String = all.iter().map(|(n, c)| format!("{n} {:016x}\n", fingerprint(c))).collect();
    if std::env::var_os("SLATE_UI_BLESS").is_some() {
        std::fs::write(path, &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(path).unwrap_or_default();
    let changed: Vec<&str> =
        got.lines().filter(|l| !want.lines().any(|w| w == *l)).map(|l| l.split(' ').next().unwrap_or(l)).collect();
    assert!(
        changed.is_empty() && got.lines().count() == want.lines().count(),
        "scenes changed: {changed:?}; look at them (SLATE_UI_OUT=DIR) and record them with SLATE_UI_BLESS=1"
    );
}

/// The glyphs the surfaces use exist in the fonts (no missing-glyph boxes).
#[test]
fn glyphs_exist() {
    let f = fonts();
    for c in "—…“”".chars() {
        assert!(f.regular.font.glyph(c) != 0, "{c:?} missing from Host Grotesk");
    }
    for c in "·$~".chars() {
        assert!(f.mono.font.glyph(c) != 0, "{c:?} missing from DM Mono");
    }
}

/// How long the parts of a 4K launcher frame take on this machine
/// (`cargo test --release -p slate-strata four_k_parts -- --ignored
/// --nocapture`; M32 phase 2).
#[test]
#[ignore]
fn four_k_parts() {
    use std::time::Instant;
    let g = Palette::GRAPHITE;
    let f = fonts();
    let sections = [Section { label: "3 matches", rows: APPS }, Section { label: "actions", rows: ACTIONS }];
    let launcher = Launcher { query: "fi", sections: &sections, selected: 0, scroll: None };
    let mut canvas = Canvas::new(3840, 2160, Color::rgb(0));
    let mut cache = GlyphCache::new();
    let mut layer = Canvas::new(3840, 2160, Color::TRANSPARENT);
    let mut lcache = GlyphCache::new();
    let copy = Canvas::new(3840, 2160, Color::rgb(0));
    for round in 0..3 {
        let t = Instant::now();
        {
            let mut p = Painter::new(&mut canvas, &mut cache, 2.0);
            desktop(&mut p, &g, &f, 0, Extras::default());
        }
        let t_desk = t.elapsed();
        let t = Instant::now();
        canvas.pixels.copy_from_slice(&copy.pixels);
        let t_copy = t.elapsed();
        let t = Instant::now();
        {
            let mut p = Painter::new(&mut canvas, &mut cache, 2.0);
            draw::dim(&mut p, g.dim_launcher, 0.5);
        }
        let t_dim = t.elapsed();
        let t = Instant::now();
        layer.clear();
        {
            let mut lp = Painter::new(&mut layer, &mut lcache, 2.0);
            draw::launcher(&mut lp, &g, &f, &launcher);
        }
        let t_layer = t.elapsed();
        let t = Instant::now();
        canvas.composite(&layer, 0.5, 3);
        let t_comp = t.elapsed();
        std::println!(
            "round {round}: desktop {t_desk:?}, copy {t_copy:?}, dim {t_dim:?}, launcher layer {t_layer:?}, composite (whole) {t_comp:?}"
        );
    }
}

/// A 4K slide frame's parts on this machine: the wallpaper, one window
/// (its content a client's buffer, as Strata draws it), the top bar
/// (`cargo test --release -p slate-strata four_k_slide -- --ignored
/// --nocapture`; M32 phase 2).
#[test]
#[ignore]
fn four_k_slide() {
    use std::time::Instant;
    let g = Palette::GRAPHITE;
    let f = fonts();
    let mut canvas = Canvas::new(3840, 2160, Color::rgb(0));
    let mut cache = GlyphCache::new();
    let wall = crate::desktop::wallpaper_for(&g, &crate::settings::Settings::default(), 3840, 2160, 2.0);
    let client = std::vec![0xFF20_2020u32; 1312 * 1100];
    let st = status();
    for round in 0..3 {
        for (name, windows) in [("no window", false), ("one window", true)] {
            let mut wm = Wm::new(1920.0, 1080.0);
            wm.shape(g.shape.title_h, g.shape.bar_h);
            if windows {
                let id = wm.add("terminal", Some("~"), false);
                wm.get_mut(id).unwrap().rect = Area::new(572.0, 214.0, 656.0, 580.0);
                wm.focus(id);
            }
            let slide = crate::motion::Slide { from: 1, shift: 600.0 + round as f32 * 37.3, dir: 1.0 };
            let ex = Extras { wall: Some(&wall), slide: Some(slide), ..Extras::default() };
            let t = Instant::now();
            {
                let mut p = Painter::new(&mut canvas, &mut cache, 2.0);
                crate::desktop::desktop(&mut p, &g, &f, &wm, &st, ex, &mut |p, _, c| {
                    let r = p.device(&c);
                    p.canvas.draw_image(r.x, r.y, 1312, 1100, &client);
                });
            }
            std::println!("round {round}: {name}: {:?}", t.elapsed());
        }
    }
}

/// The launcher drawn at 4K many times, warm (for a profiler; M32 phase 2).
#[test]
#[ignore]
fn four_k_launcher_loop() {
    let g = Palette::GRAPHITE;
    let f = fonts();
    let sections = [Section { label: "3 matches", rows: APPS }, Section { label: "actions", rows: ACTIONS }];
    let launcher = Launcher { query: "", sections: &sections, selected: 0, scroll: None };
    let mut layer = Canvas::new(3840, 2160, Color::TRANSPARENT);
    let mut cache = GlyphCache::new();
    let t = std::time::Instant::now();
    let a = draw::launcher_area(1920.0, 1080.0, &launcher).grow(200.0);
    for _ in 0..200 {
        let mut lp = Painter::new(&mut layer, &mut cache, 2.0);
        // As Strata does: only where it was drawn (the shadow's reach).
        let bounds = lp.device(&a);
        lp.canvas.clear_area(bounds);
        draw::launcher(&mut lp, &g, &f, &launcher);
    }
    std::println!("launcher: {:?} each", t.elapsed() / 200);
}

/// A window losing the focus at 4K: the first frame with it unfocused,
/// and the next (`cargo test --release -p slate-strata four_k_unfocus --
/// --ignored --nocapture`; M32 phase 2).
#[test]
#[ignore]
fn four_k_unfocus() {
    use std::time::Instant;
    let g = Palette::GRAPHITE;
    let f = fonts();
    let mut canvas = Canvas::new(3840, 2160, Color::rgb(0));
    let mut cache = GlyphCache::new();
    let wall = crate::desktop::wallpaper_for(&g, &crate::settings::Settings::default(), 3840, 2160, 2.0);
    let client = std::vec![0xFF20_2020u32; 1312 * 1100];
    let st = status();
    let mut wm = Wm::new(1920.0, 1080.0);
    wm.shape(g.shape.title_h, g.shape.bar_h);
    let id = wm.add("terminal", Some("~"), false);
    wm.get_mut(id).unwrap().rect = Area::new(572.0, 214.0, 656.0, 580.0);
    for (name, focus) in [("focused", 1.0), ("focused again", 1.0), ("unfocused", 0.3), ("unfocused again", 0.2)] {
        let look = move |_: WinId| crate::motion::Look { focus, opacity: 1.0, dy: 0.0 };
        let ex = Extras { wall: Some(&wall), look: Some(&look), dim: true, ..Extras::default() };
        let t = Instant::now();
        {
            let mut p = Painter::new(&mut canvas, &mut cache, 2.0);
            crate::desktop::desktop(&mut p, &g, &f, &wm, &st, ex, &mut |p, _, c| {
                let r = p.device(&c);
                p.canvas.draw_image(r.x, r.y, 1312, 1100, &client);
            });
        }
        std::println!("{name}: {:?}", t.elapsed());
    }
}
