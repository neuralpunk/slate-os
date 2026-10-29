// SPDX-License-Identifier: MIT OR Apache-2.0

//! The terminal scenario (M26 phase 1, ADR 0099): Strata's terminal on
//! the firmware framebuffer, driven with QEMU's keyboard and mouse.
//!
//! - **24-bit colour:** a script prints a block in a direct colour; the
//!   screen shows exactly that colour (the 256-colour cube has no such
//!   value).
//! - **Reflow:** a 150-character line wraps onto two rows in the window;
//!   maximised it is one row again, restored two.
//! - **Mouse reporting:** a program in raw mode turns on DECSET 1000 and
//!   1006 and reads what a click sends: the press and the release, at the
//!   cell clicked.
//! - **The right-click menu:** it opens over the window and Esc closes it;
//!   its Copy takes a triple-clicked line to the clipboard and its Paste
//!   types it, which runs it.
//! - **The light variant:** the terminal takes up the settings file's
//!   change by itself; direct colours stay as they are.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::qemu::{Console, base_command, monitor, mouse_index, screendump, type_keys};
use crate::{Opts, Result, image, target_dir};

/// The direct colours the scripts print.
const BLOCK: [u8; 3] = [0x12, 0x34, 0x56];
const LONG: [u8; 3] = [0x56, 0x34, 0x12];
/// The grid's line height at scale 1 (userland/terminal/src/render.rs).
const LINE_H: usize = 21;
/// The menu's overlay surface (WM_STYLE §2), graphite's and the light one's
/// window.
const OVERLAY: [u8; 3] = [0x1C, 0x1C, 0x1B];
const DAY_WINDOW: [u8; 3] = [0xF3, 0xF2, 0xF2];

/// A screendump read into memory.
struct Shot {
    width: usize,
    height: usize,
    rgb: Vec<u8>,
}

impl Shot {
    fn take(mon: &Path, name: &str) -> Result<Shot> {
        Shot::read(&screendump(mon, name)?)
    }

    fn read(path: &PathBuf) -> Result<Shot> {
        let data = std::fs::read(path).map_err(|e| format!("screenshot: {e}"))?;
        let mut fields = Vec::new();
        let mut i = 0;
        while fields.len() < 4 {
            while data.get(i).is_some_and(u8::is_ascii_whitespace) {
                i += 1;
            }
            let start = i;
            while data.get(i).is_some_and(|b| !b.is_ascii_whitespace()) {
                i += 1;
            }
            fields.push(String::from_utf8_lossy(&data[start..i]).into_owned());
        }
        let width: usize = fields[1].parse().map_err(|_| "screenshot: bad width")?;
        let height: usize = fields[2].parse().map_err(|_| "screenshot: bad height")?;
        let rgb = data.get(i + 1..i + 1 + width * height * 3).ok_or("screenshot: short")?.to_vec();
        Ok(Shot { width, height, rgb })
    }

    fn pixel(&self, x: usize, y: usize) -> [u8; 3] {
        let at = (y * self.width + x) * 3;
        [self.rgb[at], self.rgb[at + 1], self.rgb[at + 2]]
    }

    /// The box (x0, y0, x1, y1; ends exclusive) holding every pixel of
    /// colour `c`.
    fn bbox(&self, c: [u8; 3]) -> Option<(usize, usize, usize, usize)> {
        let mut b: Option<(usize, usize, usize, usize)> = None;
        for y in 0..self.height {
            for x in 0..self.width {
                if self.pixel(x, y) == c {
                    let (x0, y0, x1, y1) = b.unwrap_or((x, y, x + 1, y + 1));
                    b = Some((x0.min(x), y0.min(y), x1.max(x + 1), y1.max(y + 1)));
                }
            }
        }
        b
    }
}

/// The pointer, moved by relative steps QEMU can send (PS/2 packets carry
/// at most 255 a step).
pub(crate) struct Pointer<'a> {
    pub(crate) mon: &'a Path,
    pub(crate) at: (i64, i64),
}

impl Pointer<'_> {
    /// Into the top left corner, wherever it was.
    pub(crate) fn home(&mut self) -> Result {
        for _ in 0..8 {
            monitor(self.mon, &["mouse_move -200 -200"])?;
            std::thread::sleep(Duration::from_millis(100));
        }
        self.at = (0, 0);
        Ok(())
    }

    pub(crate) fn to(&mut self, x: usize, y: usize) -> Result {
        let (x, y) = (x as i64, y as i64);
        while self.at != (x, y) {
            let dx = (x - self.at.0).clamp(-200, 200);
            let dy = (y - self.at.1).clamp(-200, 200);
            monitor(self.mon, &[&format!("mouse_move {dx} {dy}")])?;
            self.at = (self.at.0 + dx, self.at.1 + dy);
            std::thread::sleep(Duration::from_millis(120));
        }
        std::thread::sleep(Duration::from_millis(200));
        Ok(())
    }

    /// Press and release `button` (QEMU's mask: 1 left, 2 right, 4 middle).
    pub(crate) fn click(&self, button: u8) -> Result {
        monitor(self.mon, &[&format!("mouse_button {button}"), "mouse_button 0"])
    }
}

/// The scripts, written from the serial console. Typed in the terminal,
/// QEMU's keys can spell only their names.
const SCRIPTS: &str = "cat > /tmp/c.sh <<'EOF'\n\
printf '\\033[2J\\033[3J\\033[H'\n\
printf '\\033[48;2;18;52;86m          \\033[0m\\n'\n\
echo touch /tmp/menu-pasted\n\
printf '\\033[48;2;86;52;18m'; i=0; while [ $i -lt 150 ]; do printf x; i=$((i+1)); done; printf '\\033[0m\\n'\n\
EOF\n\
cat > /tmp/m.sh <<'EOF'\n\
stty raw -echo\n\
printf '\\033[?1000h\\033[?1006h'\n\
dd bs=1 count=20 of=/tmp/mouse 2>/dev/null\n\
printf '\\033[?1006l\\033[?1000l'\n\
stty sane\n\
EOF\n\
echo scripts-$((2+2))";

fn rows_of(b: (usize, usize, usize, usize)) -> usize {
    (b.3 - b.1 + LINE_H / 2) / LINE_H
}

pub fn terminal_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    let img = image::build(o, "", "slate-terminal.img", image::Root::Disk)?;
    let mon = target_dir().join("terminal-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = base_command(o, &img)?;
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let mut con = Console::start(c)?;
    let pause = |ms: u64| std::thread::sleep(Duration::from_millis(ms));
    let result = (|| -> Result {
        con.login()?;
        con.run(SCRIPTS, "scripts-4", 10)?;
        con.send("strata &\r")?;
        con.wait_for("strata: 1280x800 at scale 1", 30)?;
        pause(800);
        monitor(&mon, &["sendkey meta_l-ret"])?;
        con.wait_for_all(&["\"terminal\" from pid", "its frame at "], 15)?;
        con.drain(300);
        // Its frame, for the resize below (ADR 0102's third addendum).
        let steps = con.last_line_with("its frame at ").unwrap_or_default();
        let frame: Vec<usize> = steps
            .rsplit("its frame at ")
            .next()
            .unwrap_or("")
            .split_whitespace()
            .filter_map(|v| v.parse::<f64>().ok().map(|v| v as usize))
            .collect();
        let [fx, fy, fw, fh] = frame[..] else { return Err(format!("no frame in {steps:?}")) };
        pause(1200);
        // 24-bit colour, and the long line on two rows.
        type_keys(&mon, "sh /tmp/c.sh\n")?;
        pause(1500);
        let shot = Shot::take(&mon, "terminal-colour.ppm")?;
        let block = shot.bbox(BLOCK).ok_or("the direct colour is not on the screen (24-bit colour)")?;
        let long = shot.bbox(LONG).ok_or("the long line's colour is not on the screen")?;
        if rows_of(long) != 2 {
            return Err(format!("the 150-character line takes {} rows in the window, not 2", rows_of(long)));
        }
        // The grid: column 0's left edge and row 0's top are the block's.
        let cell_w = (block.2 - block.0) as f64 / 10.0;
        let (gx, gy) = (block.0, block.1);
        // Reflow: maximised, the line is one row; restored, two again.
        monitor(&mon, &["sendkey meta_l-up"])?;
        pause(1200);
        let wide = Shot::take(&mon, "terminal-maximised.ppm")?;
        let rows = wide.bbox(LONG).map_or(0, rows_of);
        if rows != 1 {
            return Err(format!("maximised, the 150-character line takes {rows} rows, not 1 (reflow)"));
        }
        monitor(&mon, &["sendkey meta_l-up"])?;
        pause(1200);
        let back = Shot::take(&mon, "terminal-restored.ppm")?;
        let rows = back.bbox(LONG).map_or(0, rows_of);
        if rows != 2 || back.bbox(BLOCK) != Some(block) {
            return Err(format!("restored, the line takes {rows} rows, not 2, or the grid moved (reflow)"));
        }
        // Mouse reporting: a click on column 20 of row 3, press and release.
        type_keys(&mon, "sh /tmp/m.sh\n")?;
        pause(1000);
        let mouse = mouse_index(&mon, "PS/2 Mouse")?;
        monitor(&mon, &[&format!("mouse_set {mouse}")])?;
        let mut p = Pointer { mon: &mon, at: (0, 0) };
        p.home()?;
        let cell =
            |col: usize, row: usize| (gx + (cell_w * (col as f64 + 0.5)) as usize, gy + row * LINE_H + LINE_H / 2);
        let (x, y) = cell(20, 3);
        p.to(x, y)?;
        p.click(1)?;
        pause(800);
        con.run("tr '\\033' E < /tmp/mouse; echo; echo mouse-$((1+1))", "E[<0;21;4ME[<0;21;4m", 10)
            .map_err(|e| format!("mouse reporting: {e}"))?;
        // The menu: a triple click selects row 1's line; the right button
        // opens the menu at the pointer, Esc closes it.
        let (x, y) = cell(5, 1);
        p.to(x, y)?;
        monitor(&mon, &["mouse_button 1", "mouse_button 0", "mouse_button 1", "mouse_button 0"])?;
        monitor(&mon, &["mouse_button 1", "mouse_button 0"])?;
        pause(400);
        p.click(2)?;
        pause(600);
        let open = Shot::take(&mon, "terminal-menu.ppm")?;
        // Between its second and third rows, inside: the overlay surface.
        if open.pixel(x + 120, y + 68) != OVERLAY {
            return Err("the right button opened no menu".into());
        }
        monitor(&mon, &["sendkey esc"])?;
        pause(500);
        if Shot::take(&mon, "terminal-menu-closed.ppm")?.pixel(x + 120, y + 68) == OVERLAY {
            return Err("Esc did not close the menu".into());
        }
        // Copy (its first row), then the menu again and Paste (its second).
        p.click(2)?;
        pause(500);
        p.to(x + 60, y + 21)?;
        p.click(1)?;
        pause(400);
        p.to(x, y)?;
        p.click(2)?;
        pause(500);
        p.to(x + 120, y + 51)?;
        p.click(1)?;
        pause(400);
        type_keys(&mon, "\n")?;
        pause(800);
        con.run("test -e /tmp/menu-pasted && echo pasted-$((1+1))", "pasted-2", 10)
            .map_err(|e| format!("the menu's Copy and Paste: {e}"))?;
        // Resizing in cells (ADR 0102's third addendum): the bottom-right
        // corner dragged by about 5.5 columns and 3.5 rows stops on whole
        // cells, Strata says how many, and the shell's size is that.
        p.to(fx + fw - 2, fy + fh - 2)?;
        monitor(&mon, &["mouse_button 1"])?;
        pause(200);
        p.to(fx + fw + 45, fy + fh + 75)?;
        monitor(&mon, &["mouse_button 0"])?;
        let size = con.line_after("resized to ", 10)?;
        let (cols, rows) = size.split_once(" x ").ok_or_else(|| format!("no size in {size:?}"))?;
        type_keys(&mon, "stty size >/tmp/size\n")?;
        pause(800);
        con.run("cat /tmp/size", &format!("{rows} {cols}"), 10)
            .map_err(|e| format!("the terminal's size is not the {cols} x {rows} Strata resized it to: {e}"))?;
        // The window's login record (ADR 0143): who lists its pts.
        con.run("who | grep -c ' pts/[0-9]* .*(strata)' | sed s/^/records-/", "records-1", 10)
            .map_err(|e| format!("the terminal window's login record: {e}"))?;
        // Desktop icons: Files, there from the first session, opens the
        // home folder; a folder opens in Files, a text file in the editor,
        // by double clicks (each icon a cell of 96 x 96 from (12, 44),
        // folders first).
        con.run_seeing(
            "mkdir -p ~/Desktop/Projects && echo hi > ~/Desktop/notes.txt && echo icons-$((1+1))",
            "icons-2",
            "strata: desktop: 3 icons",
            10,
        )?;
        pause(500);
        let double = || monitor(&mon, &["mouse_button 1", "mouse_button 0", "mouse_button 1", "mouse_button 0"]);
        p.to(60, 74)?;
        double()?;
        con.wait_for("strata: desktop: opening /bin/files /root/Desktop/Projects", 10)?;
        con.wait_for("\"files\" from pid", 15)?;
        p.to(60, 170)?;
        double()?;
        let opened = con.line_after("strata: desktop: opening /bin/files", 10)?;
        if !opened.is_empty() {
            return Err(format!("the Files icon ran /bin/files {opened}, not /bin/files alone"));
        }
        con.wait_for("\"files\" from pid", 15)?;
        p.to(60, 266)?;
        double()?;
        con.wait_for("strata: desktop: opening /bin/files --open /root/Desktop/notes.txt", 10)?;
        con.wait_for("notes.txt\" from pid", 15)?;
        // All three closed (super + q), for the terminal's checks below.
        for _ in 0..3 {
            pause(800);
            monitor(&mon, &["sendkey meta_l-q"])?;
        }
        pause(800);
        // The icons worked (ADR 0156): notes.txt renamed (a click, F2, a
        // new name, Enter) and dragged into Projects; a new file put in
        // the trash with Delete; a folder made from the wallpaper's menu
        // (right button, New Folder, Enter keeps its name), then dropped on
        // Files' window, which moves it to the home folder it shows.
        p.to(60, 266)?;
        p.click(1)?;
        pause(400);
        monitor(&mon, &["sendkey f2"])?;
        pause(300);
        type_keys(&mon, "plan\n")?;
        con.wait_for("strata: desktop: notes.txt renamed plan.txt", 10)
            .map_err(|e| format!("renaming a desktop icon with F2: {e}"))?;
        pause(400);
        monitor(&mon, &["mouse_button 1"])?;
        p.to(60, 200)?;
        p.to(60, 74)?;
        monitor(&mon, &["mouse_button 0"])?;
        con.wait_for("strata: desktop: running /bin/files --move-to /root/Desktop/Projects /root/Desktop/plan.txt", 10)
            .map_err(|e| format!("dragging an icon onto a folder icon: {e}"))?;
        con.run("sleep 1; test -e ~/Desktop/Projects/plan.txt && echo moved-$((1+1))", "moved-2", 10)?;
        con.run("echo x > ~/Desktop/old.txt && echo old-$((1+1))", "old-2", 10)?;
        pause(2500);
        p.to(60, 266)?;
        p.click(1)?;
        pause(300);
        monitor(&mon, &["sendkey delete"])?;
        con.wait_for("strata: desktop: running /bin/files --trash /root/Desktop/old.txt", 10)
            .map_err(|e| format!("Delete on a desktop icon: {e}"))?;
        con.run("sleep 1; ls ~/.local/share/Trash/files | grep -c '^old' | sed s/^/trashed-/", "trashed-1", 10)?;
        p.to(60, 400)?;
        p.click(2)?;
        pause(400);
        p.to(120, 420)?;
        p.click(1)?;
        con.wait_for("strata: desktop: made New Folder", 10)
            .map_err(|e| format!("the desktop menu's New Folder: {e}"))?;
        pause(400);
        monitor(&mon, &["sendkey ret"])?;
        pause(400);
        p.to(60, 170)?;
        double()?;
        con.wait_for("\"files\" from pid", 15)?;
        pause(1500);
        p.to(60, 380)?;
        monitor(&mon, &["mouse_button 1"])?;
        p.to(300, 400)?;
        p.to(640, 420)?;
        monitor(&mon, &["mouse_button 0"])?;
        con.wait_for("files dropped on window", 10).map_err(|e| format!("an icon dropped on Files' window: {e}"))?;
        con.run(
            "sleep 1; test -d ~/New\\ Folder && ! test -e ~/Desktop/New\\ Folder && echo dropped-$((1+1))",
            "dropped-2",
            10,
        )?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(800);
        // The terminal again, for what follows.
        p.to(fx + fw / 2, fy + fh / 2)?;
        p.click(1)?;
        pause(500);
        // The light variant, taken up by the terminal itself; the direct
        // colour stays.
        con.run_seeing(
            "mkdir -p $HOME/.config/strata && echo theme=light > $HOME/.config/strata/settings && echo light-$((1+1))",
            "light-2",
            "strata: settings changed: Settings { theme: Light",
            10,
        )?;
        pause(3000);
        let day = Shot::take(&mon, "terminal-light.ppm")?;
        // Inside the grid, right of the block: no text there.
        let (bx, by) = (block.2 + 40, block.1 + 5);
        if day.pixel(bx, by) != DAY_WINDOW || day.bbox(BLOCK) != Some(block) {
            return Err(format!(
                "the terminal did not follow the light variant (background {:02x?})",
                day.pixel(bx, by)
            ));
        }
        con.run("rm $HOME/.config/strata/settings; echo dark-$((1+1))", "dark-2", 10)?;
        type_keys(&mon, "exit\n")?;
        con.wait_for("disconnected", 10)?;
        Ok(())
    })();
    if result.is_err() {
        con.drain(500);
    }
    let _ = std::fs::write(target_dir().join("terminal-scenario.log"), crate::qemu::strip_ansi(&con.log));
    if let Err(e) = result {
        con.kill();
        return Err(format!("terminal scenario: {e} (transcript in target/terminal-scenario.log)"));
    }
    con.kill();
    println!(
        "xtask: terminal scenario passed (24-bit colour, reflow on maximise and restore, mouse reporting, resizing \
         in cells, desktop icons opened, renamed, moved into a folder, trashed, made from their menu and \
         dropped on Files, the right-click menu's Copy and Paste, the light variant followed; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
