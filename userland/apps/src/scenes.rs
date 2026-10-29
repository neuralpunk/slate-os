// SPDX-License-Identifier: MIT OR Apache-2.0

//! The apps' scenes, drawn as they look in a window and fingerprinted
//! against tests/screens.txt. `SLATE_UI_OUT=DIR` saves them as PNGs to
//! look at; `SLATE_UI_BLESS=1` records a reviewed change.

use std::format;
use std::string::String;
use std::vec::Vec;

use slate_strata::fonts::{FILES, Fonts};
use slate_ui::Canvas;
use slate_ui::graphite::Palette;
use slate_ui::paint::Painter;
use slate_ui::text::GlyphCache;
use slate_ui::ui::Area;

use crate::kit::App;

fn fonts() -> Fonts<'static> {
    let read = |n: &str| -> &'static [u8] {
        let p = format!("{}/../../assets/fonts/{n}", env!("CARGO_MANIFEST_DIR"));
        std::boxed::Box::leak(std::fs::read(p).unwrap().into_boxed_slice())
    };
    Fonts::new(FILES.map(read)).unwrap()
}

/// `app` in a window `w` × `h`, in `pal`.
fn window(app: &mut dyn App, w: i32, h: i32, pal: &Palette) -> Canvas {
    let f = fonts();
    let mut canvas = Canvas::new(w, h, pal.window);
    let mut cache = GlyphCache::new();
    let mut p = Painter::new(&mut canvas, &mut cache, 1.0);
    app.draw(&mut p, pal, &f, Area::new(0.0, 0.0, w as f32, h as f32));
    canvas
}

fn scenes() -> Vec<(&'static str, Canvas)> {
    let g = Palette::GRAPHITE;
    let mut out = Vec::new();
    {
        // The icons the apps use, at the sizes they use them.
        use slate_ui::icon::Icon;
        let icons = [
            Icon::Folder,
            Icon::Letter,
            Icon::Picture,
            Icon::Archive,
            Icon::Terminal,
            Icon::Calculator,
            Icon::Clock,
            Icon::Info,
            Icon::Calendar,
            Icon::Person,
            Icon::Home,
            Icon::Disk,
            Icon::Trash,
            Icon::Search,
            Icon::ChevronLeft,
            Icon::ChevronRight,
            Icon::Backspace,
            Icon::Sliders,
            Icon::Activity,
            Icon::Download,
        ];
        let mut canvas = Canvas::new(icons.len() as i32 * 56 + 16, 104, g.window);
        let mut cache = GlyphCache::new();
        let mut p = Painter::new(&mut canvas, &mut cache, 1.0);
        for (i, ic) in icons.iter().enumerate() {
            let x = 16.0 + i as f32 * 56.0;
            p.icon(*ic, x, 16.0, 40.0, g.text_1);
            p.icon(*ic, x + 12.0, 68.0, 16.0, g.text_3);
        }
        out.push(("icons", canvas));
    }
    {
        let mut c = crate::calc::Calc::default();
        for ch in "12*(3+4".chars() {
            c.key(0, Some(ch), 0);
        }
        out.push(("calculator-typing", window(&mut c, 340, 540, &g)));
        c.key(slate_display::input::KEY_ENTER, None, 0);
        for ch in "sqrt(2)".chars() {
            c.key(0, Some(ch), 0);
        }
        c.key(slate_display::input::KEY_ENTER, None, 0);
        c.key(slate_display::input::KEY_TAB, None, 0);
        out.push(("calculator-scientific", window(&mut c, 640, 540, &g)));
        out.push(("calculator-light", window(&mut c, 640, 540, &Palette::DAY)));
    }
    {
        use crate::clock::{Alarm, Clock, Page};
        use crate::kit::Now;
        let zones = b"Europe/Paris CET-1CEST,M3.5.0,M10.5.0/3\nAsia/Kolkata IST-5:30\nAmerica/New_York EST5EDT,M3.2.0,M11.1.0\nEurope/London GMT0BST,M3.5.0/1,M10.5.0\n".to_vec();
        let rule = slate_rt::tz::Rule::resolve("Europe/London", Some(&zones)).unwrap();
        let mut c = Clock::new(rule, "Europe/London", Some(zones));
        // Saturday 24 October 2026, 21:59:30 UTC.
        let t = Now { wall: 1_792_879_170_000, mono: 1_000 };
        c.tick(t);
        c.world = ["Asia/Kolkata", "America/New_York", "Europe/Paris"].map(String::from).to_vec();
        out.push(("clock-world", window(&mut c, 420, 560, &g)));
        c.page = Page::Alarms;
        c.alarms = std::vec![
            Alarm { days: slate_strata::alarms::WEEKDAYS, ..Alarm::at("07:30").unwrap() },
            Alarm { on: false, ..Alarm::at("22:00").unwrap() },
        ];
        out.push(("clock-alarms", window(&mut c, 420, 560, &g)));
        c.page = Page::Timer;
        for ch in "500".chars() {
            c.key(0, Some(ch), 0);
        }
        c.key(slate_display::input::KEY_ENTER, None, 0);
        c.tick(Now { wall: t.wall + 75_000, mono: t.mono + 75_000 });
        out.push(("clock-timer", window(&mut c, 420, 560, &g)));
        c.page = Page::Stopwatch;
        c.stopwatch.counted = 83_400;
        c.stopwatch.laps = std::vec![31_200, 58_900];
        c.ringing = Some(crate::clock::Ring::Alarm(7, 30));
        out.push(("clock-stopwatch-ringing", window(&mut c, 420, 560, &g)));
    }
    {
        use crate::help::{Guide, Help};
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../guides/getting-started.md")).unwrap();
        let about = [
            ("release", "Slate 0.1.0-235"),
            ("kernel", "Slate 0.1.0 (Linux 6.12 interface)"),
            ("computer name", "slate"),
            ("processor", "AMD Ryzen 9 7950X 16-Core Processor × 32"),
            ("memory", "125 GiB"),
            ("disk nvme0n1", "WD_BLACK SN850X 500GB, 465.8 GiB"),
            ("graphics", "virtio-gpu (PCI 1af4:1050)"),
            ("display", "QEMU Monitor, 1280 × 800"),
            ("up for", "2 hours, 14 minutes"),
            ("desktop", "Strata"),
        ];
        let mut h = Help::default();
        h.about = about.iter().map(|(k, v)| (String::from(*k), String::from(*v))).collect();
        let install = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../guides/INSTALL.md")).unwrap();
        h.guides = std::vec![Guide::new(&text, "getting-started.md"), Guide::new(&install, "installing.md")];
        out.push(("help-about", window(&mut h, 600, 600, &g)));
        h.key(slate_display::input::KEY_TAB, None, 0);
        out.push(("help-guides", window(&mut h, 600, 600, &g)));
        h.key(slate_display::input::KEY_ENTER, None, 0);
        out.push(("help-reading", window(&mut h, 600, 600, &g)));
        out.push(("help-reading-light", window(&mut h, 600, 600, &Palette::DAY)));
        // A search: the installing guide at its first match, a table of
        // keys, and the matches marked.
        h.key(slate_display::input::KEY_ESC, None, 0);
        for c in "send the window".chars() {
            h.key(0, Some(c), 0);
        }
        out.push(("help-search", window(&mut h, 600, 600, &g)));
        h.key(slate_display::input::KEY_ENTER, None, 0);
        let _ = window(&mut h, 600, 600, &g);
        out.push(("help-table", window(&mut h, 600, 600, &g)));
        // The first guide's link chosen.
        h.key(slate_display::input::KEY_ESC, None, 0);
        h.key(slate_display::input::KEY_ESC, None, 0);
        h.key(slate_display::input::KEY_ENTER, None, 0);
        let _ = window(&mut h, 600, 600, &g);
        h.key(slate_display::input::KEY_TAB, None, 0);
        out.push(("help-link", window(&mut h, 600, 600, &g)));
    }
    {
        use crate::kit::Now;
        use crate::viewer::Viewer;
        let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/../../libs/image/tests/fixtures");
        let mut v = Viewer::open(&format!("{fixtures}/photo420-progressive.jpg"));
        v.tick(Now::default());
        v.tick(Now::default());
        v.zoom = Some(8.0);
        out.push(("viewer-photo", window(&mut v, 640, 460, &g)));
        let mut v = Viewer::open(&format!("{fixtures}/rgba8.png"));
        v.tick(Now::default());
        v.tick(Now::default());
        v.zoom = Some(8.0);
        v.turns = 1;
        out.push(("viewer-transparent-turned", window(&mut v, 640, 460, &g)));
        out.push(("viewer-light", window(&mut v, 640, 460, &Palette::DAY)));
        let mut empty = Viewer::browse("/nonexistent");
        out.push(("viewer-empty", window(&mut empty, 640, 460, &g)));
    }
    {
        use crate::archives::Manager;
        let tree = concat!(env!("CARGO_MANIFEST_DIR"), "/../../libs/zip/tests/fixtures/tree.zip");
        let mut m = Manager::open(tree);
        out.push(("archives-top", window(&mut m, 560, 520, &g)));
        m.key(slate_display::input::KEY_ENTER, None, 0);
        m.key(slate_display::input::KEY_DOWN, None, 0);
        m.status = String::from("Extracted 4 files to tree (2).");
        out.push(("archives-inside", window(&mut m, 560, 520, &g)));
        let mut make = Manager::make(std::vec![String::from("/home/ada/Holiday photos")]);
        make.key(slate_display::input::KEY_TAB, None, 0);
        out.push(("archives-make", window(&mut make, 560, 520, &g)));
        out.push(("archives-make-light", window(&mut make, 560, 520, &Palette::DAY)));
    }
    {
        use crate::editor::{Bar, Editor};
        use slate_display::input::{KEY_DOWN, KEY_END, KEY_RIGHT};
        let code = "// SPDX-License-Identifier: MIT OR Apache-2.0\n\n/* A tiny scheduler,\n   round robin. */\npub struct Scheduler {\n    quantum: u32,\n    tasks: Vec<Task>,\n}\n\nimpl Scheduler {\n    pub fn new(quantum: u32) -> Self {\n        Self { quantum, tasks: Vec::new() }\n    }\n\n    pub fn tick(&mut self) -> Option<&Task> {\n        let label = \"tick\"; // 1 of 2\n        self.tasks.first()\n    }\n}\n";
        let mut e = Editor::new(Some(String::from("/home/ada/slate/src/sched.rs")), code.as_bytes());
        for _ in 0..10 {
            e.key(KEY_DOWN, None, 0);
        }
        e.key(KEY_RIGHT, None, slate_strata_client::mods::CTRL);
        e.key(KEY_RIGHT, None, slate_strata_client::mods::CTRL | slate_strata_client::mods::SHIFT);
        e.key(KEY_RIGHT, None, slate_strata_client::mods::CTRL | slate_strata_client::mods::SHIFT);
        out.push(("editor-code", window(&mut e, 760, 520, &g)));
        e.key(0, Some('f'), slate_strata_client::mods::CTRL);
        for c in "tasks".chars() {
            e.key(0, Some(c), 0);
        }
        out.push(("editor-find", window(&mut e, 760, 520, &g)));
        // Find and replace, with regular expressions on.
        e.key(0, Some('h'), slate_strata_client::mods::CTRL);
        e.key(0, Some('r'), slate_strata_client::mods::ALT);
        for c in "Vec".chars() {
            e.key(0, Some(c), 0);
        }
        out.push(("editor-replace", window(&mut e, 760, 520, &g)));
        // Long lines wrapped in a narrow window.
        let notes = "# Scheduling\n\nEach task runs for one quantum, then the next one in the queue gets the CPU; a task that blocks gives the rest of its quantum away.\n\n- Round robin keeps it fair.\n- Priorities come later.\n";
        let mut w = Editor::new(Some(String::from("/home/ada/notes.md")), notes.as_bytes());
        w.key(0, Some('z'), slate_strata_client::mods::ALT);
        w.key(KEY_DOWN, None, 0);
        w.key(KEY_DOWN, None, 0);
        w.key(KEY_DOWN, None, 0);
        out.push(("editor-wrap", window(&mut w, 440, 300, &g)));
        let md = "# Notes\n\nSlate's **editor** keeps\nthe file as it was.\n\n    indented code\n";
        let mut m = Editor::new(Some(String::from("/home/ada/notes.md")), md.as_bytes());
        m.key(KEY_END, None, 0);
        m.key(0, Some('!'), 0);
        m.bar = Some(Bar::Close);
        out.push(("editor-close-light", window(&mut m, 760, 420, &Palette::DAY)));
    }
    {
        use crate::files::{Files, Place, View};
        use crate::fsops::{Mount, Trash};
        // A home made for the scenes, every time the same.
        let home = std::env::temp_dir().join(format!("slate-files-scene-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let h = home.to_string_lossy().into_owned();
        for d in ["Documents/letters", "Downloads", "Pictures", "Music"] {
            std::fs::create_dir_all(format!("{h}/{d}")).unwrap();
        }
        let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/../../libs/image/tests/fixtures");
        for (from, to) in [("photo420.jpg", "beach.jpg"), ("rgba8.png", "logo.png"), ("photo444.jpg", "garden.jpg")] {
            std::fs::copy(format!("{fixtures}/{from}"), format!("{h}/Pictures/{to}")).unwrap();
        }
        std::fs::write(format!("{h}/Documents/plan.txt"), "a".repeat(1300)).unwrap();
        std::fs::write(format!("{h}/Documents/budget 2026.ods"), std::vec![0u8; 48_000]).unwrap();
        std::fs::write(format!("{h}/Documents/photos.tar.gz"), std::vec![0u8; 2_400_000]).unwrap();
        // Noon UTC on Monday 19 October 2020: the same date everywhere.
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_603_108_800);
        for e in walk(&home) {
            let f = std::fs::File::options().write(e.is_file()).read(true).open(&e).unwrap();
            f.set_modified(t).unwrap();
        }
        let fixed = |f: &mut Files| {
            f.disks = std::vec![
                Mount { at: "/".into(), device: "/dev/dm-0".into(), fs: "slatefs".into() },
                Mount { at: "/mnt/backup".into(), device: "/dev/sdb1".into(), fs: "ext4".into() },
            ];
            f.show_free = false;
            f.trash = Some(Trash { dir: format!("{h}/.local/share/Trash"), top: None });
        };
        let mut f = Files::new(&h, Place::Folder(format!("{h}/Documents")));
        fixed(&mut f);
        f.load();
        f.key(slate_display::input::KEY_DOWN, None, 0);
        f.key(slate_display::input::KEY_DOWN, None, slate_strata_client::mods::SHIFT);
        out.push(("files-list", window(&mut f, 900, 600, &g)));
        // The themes in colour (ADR 0167): selection, the chosen place and
        // folders in their accents.
        out.push(("files-list-copper-noir", window(&mut f, 900, 600, &Palette::COPPER_NOIR)));
        out.push(("files-list-sediment", window(&mut f, 900, 600, &Palette::SEDIMENT)));
        f.right_click(400.0, 155.0);
        out.push(("files-menu", window(&mut f, 900, 600, &g)));
        // Bookmarks in the sidebar, and a file's properties.
        f.menu = None;
        f.bookmarks = std::vec![format!("{h}/Documents/letters"), String::from("/mnt/backup/photos")];
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(format!("{h}/Documents/plan.txt"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut pr = crate::files::Props::of(&[format!("{h}/Documents/plan.txt")], &h);
        // (The account the scenes run as differs from machine to machine.)
        (pr.owner, pr.mine, pr.focus) = (String::from("ada, group ada"), true, 4);
        f.props = Some(pr);
        out.push(("files-properties", window(&mut f, 900, 600, &g)));
        out.push(("files-properties-light", window(&mut f, 900, 600, &Palette::DAY)));
        f.props = None;
        // Copying in the background: how far it is.
        f.transfer = Some(crate::files::Transfer {
            list: std::vec![(String::from("/a"), String::from("/b")); 4],
            cut: false,
            total: 2_400_000_000,
            done: 1_000_000_000,
            at: 1,
            removing: false,
            job: None,
        });
        out.push(("files-copying", window(&mut f, 900, 600, &g)));
        f.transfer = None;
        // Dragging the chosen files onto the letters folder.
        f.dragging = Some(crate::files::Dragging {
            paths: std::vec![format!("{h}/Documents/budget 2026.ods"), format!("{h}/Documents/photos.tar.gz")],
            x: 330.0,
            y: 98.0,
            target: Some(Place::Folder(format!("{h}/Documents/letters"))),
            copy: false,
        });
        out.push(("files-dragging", window(&mut f, 900, 600, &g)));
        f.dragging = None;
        // Searching names and text.
        f.key(0, Some('f'), slate_strata_client::mods::CTRL);
        for c in "budget".chars() {
            f.key(0, Some(c), 0);
        }
        f.key(slate_display::input::KEY_TAB, None, 0);
        out.push(("files-search-text", window(&mut f, 900, 600, &g)));
        f.search = None;
        f.bookmarks.clear();
        let mut p = Files::new(&h, Place::Folder(format!("{h}/Pictures")));
        fixed(&mut p);
        p.load();
        p.view = View::Grid;
        let _ = window(&mut p, 900, 600, &g);
        for _ in 0..4 {
            p.tick(crate::kit::Now::default());
        }
        out.push(("files-grid", window(&mut p, 900, 600, &g)));
        out.push(("files-grid-light", window(&mut p, 900, 600, &Palette::DAY)));
        // Without thumbnails: the file icons (a folder, a spreadsheet, an
        // archive, text).
        let mut d = Files::new(&h, Place::Folder(format!("{h}/Documents")));
        fixed(&mut d);
        d.load();
        d.view = View::Grid;
        out.push(("files-grid-documents", window(&mut d, 900, 600, &g)));
        out.push(("files-grid-documents-light", window(&mut d, 900, 600, &Palette::DAY)));
        let trash = Trash { dir: format!("{h}/.local/share/Trash"), top: None };
        trash.put(&format!("{h}/Documents/plan.txt"), 1_603_108_800).unwrap();
        f.menu = None;
        f.go(Place::Trash);
        out.push(("files-trash", window(&mut f, 900, 600, &g)));
        std::fs::remove_dir_all(&home).unwrap();
    }
    {
        use crate::calendar::{Cal, View};
        use slate_pim::date::Date;
        let dir = std::env::temp_dir().join(format!("slate-cal-scene-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dir = dir.to_string_lossy().into_owned();
        let d = |m: u8, day: u8| Date::new(2026, m, day).unwrap();
        let mut c = Cal::new(&dir, d(10, 24), None, slate_rt::tz::Rule::UTC);
        let work = "BEGIN:VCALENDAR\r\nX-WR-CALNAME:Work\r\nBEGIN:VEVENT\r\nUID:1\r\nDTSTART:20261026T090000\r\nDTEND:20261026T093000\r\nRRULE:FREQ=WEEKLY;BYDAY=MO,WE,FR;COUNT=12\r\nSUMMARY:Stand-up\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:2\r\nDTSTART:20261024T140000\r\nDTEND:20261024T153000\r\nSUMMARY:Design review\r\nLOCATION:Room 4\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let personal = "BEGIN:VCALENDAR\r\nX-WR-CALNAME:Personal\r\nBEGIN:VEVENT\r\nUID:3\r\nDTSTART;VALUE=DATE:20261030\r\nDTEND;VALUE=DATE:20261102\r\nSUMMARY:Lyon by train\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:4\r\nDTSTART:20261024T190000\r\nDTEND:20261024T220000\r\nSUMMARY:Dinner with Grace\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:5\r\nDTSTART:20261024T080000\r\nDTEND:20261024T090000\r\nSUMMARY:Run\r\nRRULE:FREQ=DAILY;COUNT=40\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        c.import("work.ics", work);
        c.import("personal.ics", personal);
        c.day = d(10, 24);
        c.status.clear();
        out.push(("calendar-month", window(&mut c, 980, 680, &g)));
        c.key(slate_display::input::KEY_ENTER, None, 0);
        c.key(slate_display::input::KEY_DOWN, None, 0);
        out.push(("calendar-day", window(&mut c, 980, 680, &g)));
        c.key(slate_display::input::KEY_ENTER, None, 0);
        out.push(("calendar-form", window(&mut c, 980, 680, &g)));
        c.key(slate_display::input::KEY_ESC, None, 0);
        c.key(slate_display::input::KEY_ESC, None, 0);
        c.view = View::Agenda;
        out.push(("calendar-agenda-light", window(&mut c, 980, 680, &Palette::DAY)));
        std::fs::remove_dir_all(&dir).unwrap();
    }
    {
        use crate::contacts::Book;
        let dir = std::env::temp_dir().join(format!("slate-contacts-scene-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = format!("{}/contacts.vcf", dir.to_string_lossy());
        let mut b = Book::new(&path);
        let cards = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:1\r\nFN:Ada Lovelace\r\nN:Lovelace;Ada;;;\r\nTEL;TYPE=cell:+44 20 7946 0958\r\nEMAIL;TYPE=work:ada@example.org\r\nADR;TYPE=home:;;12 St James's Square;London;;SW1Y 4JH;United Kingdom\r\nORG:Analytical Engines\r\nTITLE:Mathematician\r\nBDAY:18151210\r\nNOTE:Wrote the first program, on paper.\r\nEND:VCARD\r\nBEGIN:VCARD\r\nVERSION:4.0\r\nUID:2\r\nFN:Grace Hopper\r\nN:Hopper;Grace;;;\r\nEMAIL:grace@example.com\r\nEND:VCARD\r\nBEGIN:VCARD\r\nVERSION:4.0\r\nUID:3\r\nFN:Katherine Johnson\r\nN:Johnson;Katherine;;;\r\nORG:NASA\r\nEND:VCARD\r\nBEGIN:VCARD\r\nVERSION:4.0\r\nUID:4\r\nFN:Alan Turing\r\nN:Turing;Alan;;;\r\nTEL:+44 161 555 0100\r\nEND:VCARD\r\n";
        b.import("people.vcf", cards);
        b.status.clear();
        b.key(slate_display::input::KEY_DOWN, None, 0);
        b.key(slate_display::input::KEY_DOWN, None, 0);
        out.push(("contacts-card", window(&mut b, 860, 600, &g)));
        b.key(slate_display::input::KEY_ENTER, None, 0);
        out.push(("contacts-form", window(&mut b, 860, 600, &g)));
        b.key(slate_display::input::KEY_ESC, None, 0);
        for c in "tur".chars() {
            b.key(0, Some(c), 0);
        }
        out.push(("contacts-search-light", window(&mut b, 860, 600, &Palette::DAY)));
        std::fs::remove_dir_all(&dir).unwrap();
    }
    {
        // The System Monitor (ADR 0112): processes, ending one, the
        // resources over a minute, the file systems.
        use crate::sysmon::{Confirm, Sample};
        use slate_sysinfo::load::{CpuTime, DiskCount, Memory, Mount, NetCount};
        use slate_sysinfo::procs::Proc;
        let mut m = crate::sysmon::tests::monitor();
        out.push(("monitor-processes", window(&mut m, 900, 620, &g)));
        m.confirm = Some(Confirm { pid: 77, name: "firefox".into(), focus: 1 });
        out.push(("monitor-ending", window(&mut m, 900, 620, &g)));
        m.confirm = None;
        // The tree, and a process's details (made up: the same on every
        // machine).
        m.tree = true;
        out.push(("monitor-tree", window(&mut m, 900, 620, &g)));
        use slate_sysinfo::procs::{Io, Thread};
        let thread = |tid: i32, name: &str, state: char| Thread { tid, name: name.into(), state, ticks: 0 };
        m.selected = Some(77);
        m.details = Some(crate::sysmon::Details {
            pid: 77,
            threads: std::vec![
                thread(77, "firefox", 'S'),
                thread(81, "Renderer", 'R'),
                thread(82, "DOM Worker", 'S'),
                thread(85, "Socket Thread", 'S'),
            ],
            files: Some(std::vec![
                (0, "/dev/null".into()),
                (1, "pipe:[4021]".into()),
                (2, "pipe:[4021]".into()),
                (3, "socket:[5512]".into()),
                (4, "/home/ada/.mozilla/firefox/places.sqlite".into()),
            ]),
            io: Some(Io { rchar: 81_000_000, wchar: 12_400_000, read_bytes: 64_000_000, write_bytes: 9_800_000 }),
            nice: 5,
        });
        out.push(("monitor-details", window(&mut m, 900, 620, &g)));
        out.push(("monitor-details-light", window(&mut m, 900, 620, &Palette::DAY)));
        m.details = None;
        m.tree = false;
        // Thirty samples of a machine with four processors getting busier.
        let mut m = crate::sysmon::Monitor::new(std::collections::BTreeMap::new(), 0);
        let (mut busy, mut total, mut rx, mut rd) = (0u64, 0u64, 0u64, 0u64);
        for i in 0..30u64 {
            let load = 40 + (i * 37 % 120);
            busy += load;
            total += 400;
            rx += 200_000 + i * 30_000;
            rd += 1000 * (i % 7);
            let cpus = core::iter::once(CpuTime { busy, total })
                .chain((0..4).map(|c| CpuTime { busy: busy / 4 + c * i * 3, total: total / 4 + c * i * 3 }))
                .collect();
            let s = Sample {
                procs: std::vec![Proc { pid: 1, name: "slinit".into(), ..Proc::default() }],
                cpus,
                memory: Memory { total: 4 << 20, available: (3 << 20) - i * 20_000, cached: 600_000, buffers: 40_000 },
                net: std::vec![NetCount { name: "eth0".into(), received: rx, sent: rx / 5 }],
                disks: std::vec![DiskCount { name: "vda".into(), read: rd, written: rd / 2 }],
                mounts: std::vec![
                    (
                        Mount { source: "/dev/dm-0".into(), path: "/".into(), fs: "slatefs".into() },
                        499_000_000_000,
                        401_000_000_000
                    ),
                    (
                        Mount { source: "/dev/nvme0n1p1".into(), path: "/boot/efi".into(), fs: "vfat".into() },
                        1_070_000_000,
                        60_000_000
                    ),
                ],
            };
            m.sample(s, i as i64 * 2000);
        }
        m.tab = 1;
        out.push(("monitor-resources", window(&mut m, 900, 620, &g)));
        // Its chart and meters in the themes' accents (ADR 0167).
        out.push(("monitor-resources-copper-noir", window(&mut m, 900, 620, &Palette::COPPER_NOIR)));
        out.push(("monitor-resources-sediment", window(&mut m, 900, 620, &Palette::SEDIMENT)));
        m.tab = 2;
        out.push(("monitor-file-systems-light", window(&mut m, 900, 620, &Palette::DAY)));
        // App Center (ADR 0125): not set up; the catalog; an app's page.
        let mut setup = crate::appcenter::Center::new("/nonexistent", false);
        out.push(("appcenter-setup", window(&mut setup, 980, 680, &g)));
        let mut c = crate::appcenter::tests::center();
        // Their icons: a picture of the image library's, for some.
        let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/../../libs/image/tests/fixtures");
        let photo = slate_image::decode(&std::fs::read(format!("{fixtures}/rgba8.png")).unwrap()).unwrap();
        c.set_icon("org.inkscape.Inkscape.png", Some(photo.clone()));
        c.set_icon("org.gnome.Calculator.png", Some(photo));
        out.push(("appcenter-all", window(&mut c, 980, 680, &g)));
        out.push(("appcenter-all-light", window(&mut c, 980, 680, &Palette::DAY)));
        c.page = Some(String::from("org.gnome.Calculator"));
        out.push(("appcenter-page-installed", window(&mut c, 980, 680, &g)));
        c.page = Some(String::from("org.inkscape.Inkscape"));
        out.push(("appcenter-page", window(&mut c, 980, 680, &g)));
        // Installing it: a spinner, the time taken and what Flatpak says.
        c.work.push(crate::appcenter::Work::Installing(String::from("org.inkscape.Inkscape"), false));
        c.status = Some((String::from("Installing Inkscape…"), false));
        c.said = Some(String::from("Installing runtime/org.freedesktop.Platform/x86_64/25.08"));
        c.now = 83_250;
        out.push(("appcenter-installing", window(&mut c, 980, 680, &g)));
        // Setting the runtime up: how far, from slate-linux setup's file.
        let mut setup = crate::appcenter::Center::new("/nonexistent", false);
        setup.work.push(crate::appcenter::Work::SettingUp);
        setup.setup = crate::kit::SetupProgress::parse("packages 34 159 mesa");
        setup.now = 4_250;
        out.push(("appcenter-setting-up", window(&mut setup, 980, 680, &g)));
        out.push(("appcenter-setting-up-light", window(&mut setup, 980, 680, &Palette::DAY)));
    }
    {
        // Disks: a stick beside the system's disk; the system's encrypted
        // root with its subvolumes; a new partition; erasing, in light.
        use slate_display::input::{KEY_RIGHT, KEY_UP};
        let mut d = crate::disks::tests::sample();
        out.push(("disks-stick", window(&mut d, 940, 620, &g)));
        d.key(KEY_UP, None, 0);
        d.key(KEY_RIGHT, None, 0);
        out.push(("disks-system", window(&mut d, 940, 620, &g)));
        let mut d = crate::disks::tests::sample();
        d.key(KEY_RIGHT, None, 0);
        d.key(0, Some('n'), 0);
        out.push(("disks-new-partition", window(&mut d, 940, 620, &g)));
        let mut d = crate::disks::tests::sample();
        d.key(0, Some('e'), 0);
        out.push(("disks-erase-light", window(&mut d, 940, 620, &Palette::DAY)));
    }
    {
        // The Software Updater: updates waiting; installed, with a
        // restart to come; rolling back, in light.
        use crate::updater::Work;
        let mut u = crate::updater::tests::sample();
        out.push(("updater-updates", window(&mut u, 680, 640, &g)));
        // As after the install: the new system starts next.
        u.systems
            .insert(0, slate_rt::subvol::Subvol { id: 4, name: "system-4".into(), flags: std::vec!["default".into()] });
        u.systems[1].flags = std::vec!["mounted-here".into(), "fallback".into()];
        u.systems.truncate(2);
        u.restart_wanted = true;
        u.finished(Work::Installing, Ok(String::new()));
        out.push(("updater-installed", window(&mut u, 680, 640, &g)));
        u.key(0, Some('r'), 0);
        out.push(("updater-rollback-light", window(&mut u, 680, 640, &Palette::DAY)));
        // With Flatpak apps (ADR 0114): one to update, one to roll back.
        let mut u = crate::updater::tests::with_apps();
        u.app = 1;
        out.push(("updater-apps", window(&mut u, 680, 760, &g)));
        // The Web Browser's first use (ADR 0115): offered with the runtime
        // to set up, fetching, and failed.
        use crate::browser::{Browser, FIREFOX, Needs, Stage};
        let mut b = Browser::new(FIREFOX, Needs { setup: true, fetch: true }, Vec::new());
        out.push(("browser-offer", window(&mut b, 600, 440, &g)));
        let mut b = Browser::new(FIREFOX, Needs { setup: false, fetch: true }, Vec::new());
        b.stage = Stage::Fetching;
        b.said = Some(String::from("Installing app/org.mozilla.firefox/x86_64/stable"));
        b.now = 700;
        out.push(("browser-fetching", window(&mut b, 600, 440, &g)));
        let mut s = Browser::new(FIREFOX, Needs { setup: true, fetch: true }, Vec::new());
        s.stage = Stage::SettingUp;
        s.setup = crate::kit::SetupProgress::parse("packages 120 159 xwayland");
        out.push(("browser-setting-up", window(&mut s, 600, 440, &g)));
        b.stage = Stage::Failed("Firefox wasn't fetched: couldn't fetch Flathub's description".into());
        out.push(("browser-failed-light", window(&mut b, 600, 440, &Palette::DAY)));
        // Installed, but it didn't start: the window comes back to say so.
        let mut b = Browser::new(FIREFOX, Needs { setup: false, fetch: false }, Vec::new());
        b.stage = Stage::Failed(crate::browser::failure_text(FIREFOX, 1, "Error: cannot open display: :0\n"));
        out.push(("browser-didnt-start", window(&mut b, 600, 320, &g)));
        // Everything at once: the buttons take two rows.
        u.updates = crate::updater::tests::sample().updates;
        u.restart_wanted = true;
        out.push(("updater-apps-all", window(&mut u, 680, 760, &g)));
    }
    out
}

/// Every path under `dir`, the deepest first.
fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        }
        out.push(p);
    }
    out
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
            std::fs::write(format!("{dir}/apps-{name}.png"), slate_ui::png::encode(c)).unwrap();
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

/// The symbols the apps draw exist in the fonts (no missing-glyph boxes).
#[test]
fn glyphs_exist() {
    let f = fonts();
    let missing = |face: &slate_ui::text::Face<'_>, s: &str| -> String {
        s.chars().filter(|c| face.font.glyph(*c) == 0).collect()
    };
    let (a, b) = (missing(&f.medium, "÷×−π²√…·–"), missing(&f.mono, "÷×−π√…·–"));
    assert!(a.is_empty() && b.is_empty(), "missing from Host Grotesk: {a:?}; from DM Mono: {b:?}");
}
