// SPDX-License-Identifier: MIT OR Apache-2.0

//! The apps scenario (M28, ADR 0104): Slate's apps in Strata, opened from
//! the launcher and driven with QEMU's keyboard. The apps say what they
//! do on the serial console when `SLATE_APPS_TRACE` is set.
//!
//! - **Calculator:** a sum with brackets, the scientific keys in degrees,
//!   then radians.
//! - **Clock:** a three-second timer rings; a place is added and kept in
//!   the person's file; an alarm set for the next minute rings.
//! - **Image Viewer:** a JPEG and a PNG, put in ~/Pictures, shown in
//!   turn.
//! - **Archive Manager:** a folder made into a zip, removed, and
//!   extracted from the zip again.
//! - **Text Editor:** a new file typed and saved; an edit undone, and
//!   closing with an unsaved change saved from the question.
//! - **Files:** a folder opened by typing its name, a copy pasted, moved
//!   to the trash and put back, a file opened in the Text Editor; a file
//!   dragged out of its window onto the desktop, put back with ctrl + z
//!   on the desktop, and dragged again with ctrl held: a copy.
//! - **Calendar:** a file imported, an event added, all exported.
//! - **Contacts:** cards imported, a new one typed in.
//! - **Web Browser:** with no browser yet, it offers Firefox from
//!   Flathub, the runtime to set up first; Esc closes it.
//! - **Help:** About this system reads the machine (its graphics and
//!   display too); a guide opens, its link to another, and a search.

use std::time::{Duration, Instant};

use crate::qemu::{Console, base_command, monitor, mouse_index, type_keys};
use crate::terminal::Pointer;
use crate::{Opts, Result, image, target_dir};

/// Open `name` from the launcher, and wait for its window.
pub fn launch(mon: &std::path::Path, con: &mut Console, typed: &str, window: &str) -> Result {
    monitor(mon, &["sendkey meta_l-spc"])?;
    std::thread::sleep(Duration::from_millis(600));
    type_keys(mon, typed)?;
    std::thread::sleep(Duration::from_millis(300));
    type_keys(mon, "\n")?;
    con.wait_for(&format!("\"{window}\" from pid"), 15)?;
    std::thread::sleep(Duration::from_millis(1200));
    Ok(())
}

/// Numbers after `marker` in the last line that has it.
fn numbers_after(con: &Console, marker: &str) -> Result<Vec<f64>> {
    let line = con.last_line_with(marker).ok_or_else(|| format!("no {marker:?} line"))?;
    Ok(line.rsplit(marker).next().unwrap_or("").split_whitespace().filter_map(|v| v.parse().ok()).collect())
}

/// A file dragged out of Files' window onto the desktop is moved there
/// (ADR 0156); ctrl + z on the desktop puts it back, and dragged again
/// with ctrl held it is copied (its addendum). Files says where its first
/// row is, Strata where its window went.
fn files_to_desktop(mon: &std::path::Path, con: &mut Console) -> Result {
    let pause = |ms: u64| std::thread::sleep(Duration::from_millis(ms));
    con.run("mkdir -p $HOME/Drop $HOME/Desktop && echo m > $HOME/Drop/moved.txt && echo drop-$((1+1))", "drop-2", 10)?;
    con.send("files &\r")?;
    // Its window's number, from Strata's line for it.
    con.line_after("\"files\" from pid", 15)?;
    let line = con.last_line_with("\"files\" from pid").unwrap_or_default();
    let id = line.split("strata: window ").nth(1).and_then(|r| r.split(' ').next()).unwrap_or("").to_string();
    let frame = con.line_after(&format!("strata: window {id} placed at "), 10)?;
    let frame: Vec<f64> = frame.split_whitespace().filter_map(|v| v.parse().ok()).collect();
    let [fx, fy, fw, _] = frame[..] else { return Err(format!("no frame for Files in {frame:?}")) };
    pause(1200);
    type_keys(mon, "Drop\n")?;
    con.wait_for("files: in ~/Drop", 10)?;
    pause(800);
    let [rx, ry, _, rh] = numbers_after(con, "files: first row at ")?[..] else {
        return Err("Files didn't say where its rows are".into());
    };
    // The row's name, on the screen (the frame's title bar is 36 high, its
    // border 1 wide); the desktop beside the window.
    let row = ((fx + 1.0 + rx + 60.0) as usize, (fy + 36.0 + ry + rh / 2.0) as usize);
    let beside = if fx + fw + 80.0 < 1270.0 { (fx + fw + 60.0) as usize } else { (fx - 60.0).max(20.0) as usize };
    let mouse = mouse_index(mon, "HID Mouse")?;
    monitor(mon, &[&format!("mouse_set {mouse}")])?;
    let mut p = Pointer { mon, at: (0, 0) };
    let drag = |p: &mut Pointer<'_>| -> Result {
        p.home()?;
        p.to(row.0, row.1)?;
        monitor(mon, &["mouse_button 1"])?;
        p.to(row.0 + 30, row.1 + 10)?;
        p.to(beside, 420)?;
        monitor(mon, &["mouse_button 0"])
    };
    drag(&mut p)?;
    con.wait_for("strata: desktop: 1 dropped from a window into /root/Desktop", 10)
        .map_err(|e| format!("a file dragged from Files onto the desktop: {e}"))?;
    con.run(
        "sleep 1; test -e ~/Desktop/moved.txt && ! test -e ~/Drop/moved.txt && echo on-desk-$((1+1))",
        "on-desk-2",
        10,
    )?;
    // ctrl + z on the desktop (a click on the wallpaper gives it the keys).
    p.click(1)?;
    pause(400);
    monitor(mon, &["sendkey ctrl-z"])?;
    con.wait_for("strata: desktop: undo", 10).map_err(|e| format!("ctrl + z on the desktop: {e}"))?;
    con.wait_for("files: Undone.", 10)?;
    con.run("test -e ~/Drop/moved.txt && ! test -e ~/Desktop/moved.txt && echo back-$((1+1))", "back-2", 10)?;
    // Again with ctrl held to the end: a copy.
    p.to(fx as usize + 200, fy as usize + 12)?;
    p.click(1)?;
    pause(1500);
    monitor(mon, &["sendkey ctrl 6000"])?;
    drag(&mut p)?;
    con.wait_for("strata: desktop: 1 copied from a window into /root/Desktop", 10)
        .map_err(|e| format!("a file dragged from Files with ctrl held: {e}"))?;
    con.run(
        "sleep 1; test -e ~/Desktop/moved.txt && test -e ~/Drop/moved.txt && echo copied-$((1+1))",
        "copied-2",
        10,
    )?;
    // Closed from the console: keys sent now would wait behind the held
    // ctrl in QEMU's queue and reach the next window.
    let pid = line.split("from pid ").nth(1).and_then(|r| r.split(' ').next()).unwrap_or("").to_string();
    pause(6000);
    con.run_seeing(
        &format!("kill {pid}; rm -r $HOME/Drop $HOME/Desktop/moved.txt && echo tidy-$((1+1))"),
        "tidy-2",
        &format!("client {pid}: disconnected"),
        10,
    )?;
    Ok(())
}

pub fn apps_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    let img = image::build(o, "", "slate-apps.img", image::Root::Disk)?;
    let mon = target_dir().join("apps-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = base_command(o, &img)?;
    c.args(["-device", "qemu-xhci,id=xhci", "-device", "usb-mouse,bus=xhci.0"]);
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let mut con = Console::start(c)?;
    let pause = |ms: u64| std::thread::sleep(Duration::from_millis(ms));
    let result = (|| -> Result {
        con.login()?;
        con.run("ls /usr/share/doc/slate/guides | tr '\\n' ,", "getting-started.md,installing.md,", 10)?;
        con.send("export SLATE_APPS_TRACE=1; strata &\r")?;
        con.wait_for("strata: 1280x800 at scale 1", 30)?;
        pause(800);
        // The Calculator, from the launcher.
        launch(&mon, &mut con, "calc", "calculator")?;
        type_keys(&mon, "12*(3+4)\n")?;
        con.wait_for("calculator: 12*(3+4) = 84", 10)?;
        type_keys(&mon, "\tsin(30)\n")?;
        con.wait_for("calculator: sin(30) = 0.5", 10)?;
        monitor(&mon, &["sendkey ctrl-d"])?;
        type_keys(&mon, "cos(pi)\n")?;
        con.wait_for("calculator: cos(pi) = -1", 10)?;
        type_keys(&mon, "2/0\n")?;
        con.wait_for("calculator: 2/0: DivideByZero", 10)?;
        // Another base, the memory and a hyperbolic function (Esc first:
        // after an error, typing mends the expression).
        monitor(&mon, &["sendkey esc"])?;
        type_keys(&mon, "0x1f+1\n")?;
        con.wait_for("calculator: 0x1f+1 = 32", 10)?;
        monitor(&mon, &["sendkey ctrl-m"])?;
        con.wait_for("calculator: memory 32", 10)?;
        type_keys(&mon, "mem/2+sinh 0\n")?;
        con.wait_for("calculator: mem/2+sinh 0 = 16", 10)?;
        monitor(&mon, &["sendkey ctrl-b"])?;
        con.wait_for("calculator: base 16: 0x10", 10)?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(800);
        // Solitaire (ADR 0177): dealt (it says so before its window
        // comes), the stock turned by key.
        launch(&mon, &mut con, "solit", "solitaire")?;
        type_keys(&mon, "d")?;
        con.wait_for("solitaire: turned the stock (23 left)", 10)?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(600);
        // Mines: the first square opened by key is never a mine.
        launch(&mon, &mut con, "mines", "mines")?;
        monitor(&mon, &["sendkey ret"])?;
        con.wait_for("mines: opened, ", 10)?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(600);
        // The Clock: a timer, a place, and an alarm for the next minute.
        launch(&mon, &mut con, "clock", "clock")?;
        type_keys(&mon, "\t\t3\n")?;
        con.wait_for("clock: the timer rang", 10)?;
        type_keys(&mon, "\n\t\tatokyo\n")?;
        pause(800);
        con.run("cat $HOME/.config/strata/clock", "zone=Asia/Tokyo", 10)?;
        // Far enough from the minute's end that the alarm can be typed in
        // time.
        con.run("while [ $(date +%S) -gt 45 ]; do sleep 1; done; echo minute-$((1+1))", "minute-2", 30)?;
        // The marker is split as typed, so the command's echo isn't it.
        con.send("echo \"n\"\"ext=$(date -d '+1 minute' +%H%M)\"\r")?;
        let next = con.line_after("next=", 10)?;
        let next = next.trim();
        if next.len() != 4 {
            return Err(format!("the next minute from date: {next:?}"));
        }
        type_keys(&mon, &format!("\ta{next}\n"))?;
        pause(600);
        // Once (d: weekdays, weekends, once), so whatever today is.
        type_keys(&mon, "ddd")?;
        pause(600);
        let at = format!("{}:{}", &next[..2], &next[2..]);
        con.run("cat $HOME/.config/strata/clock", &format!("alarm={at} on once"), 10)?;
        // With the Clock closed, Strata opens it to ring; once, it is then
        // off.
        monitor(&mon, &["sendkey meta_l-q"])?;
        con.wait_for("disconnected", 10)?;
        con.wait_for_all(
            &[&format!("strata: the alarm at {at}: opening the Clock"), &format!("clock: the alarm at {at} rang")],
            75,
        )?;
        pause(800);
        con.run("cat $HOME/.config/strata/clock", &format!("alarm={at} off once"), 10)?;
        type_keys(&mon, "\n")?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(800);
        // Help: the machine described, and a guide read.
        // The Image Viewer: two pictures put in ~/Pictures, written from
        // the console with Slate's own base64.
        let fixtures = crate::root().join("libs/image/tests/fixtures");
        for name in ["photo420.jpg", "rgba8.png"] {
            let data = std::fs::read(fixtures.join(name)).map_err(|e| format!("{name}: {e}"))?;
            let text = base64(&data);
            con.run(
                &format!(
                    "mkdir -p $HOME/Pictures; base64 -d > $HOME/Pictures/{name} <<'EOF'\n{text}\nEOF\necho put-$((1+1))"
                ),
                "put-2",
                20,
            )?;
        }
        launch(&mon, &mut con, "image", "images")?;
        con.wait_for("image-viewer: photo420.jpg 61x45 JPEG", 10)?;
        type_keys(&mon, " ")?;
        con.wait_for("image-viewer: rgba8.png 37x23 PNG", 10)?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(800);
        // The Archive Manager: a folder made into a zip, the folder
        // removed, the zip extracted again (started from the console,
        // as Files will start it, with the paths).
        con.run(
            "mkdir -p $HOME/trip/day1 && echo rain > $HOME/trip/day1/notes.txt && echo go > $HOME/trip/plan.txt \
             && echo tree-$((1+1))",
            "tree-2",
            10,
        )?;
        con.send("archive-manager $HOME/trip &\r")?;
        con.wait_for("\"archives\" from pid", 15)?;
        pause(1200);
        type_keys(&mon, "\n")?;
        con.wait_for("archive-manager: made /root/trip.zip", 15)?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(800);
        con.run("rm -r $HOME/trip && echo gone-$((1+1))", "gone-2", 10)?;
        con.send("archive-manager $HOME/trip.zip &\r")?;
        con.wait_for("\"archives\" from pid", 15)?;
        pause(1200);
        type_keys(&mon, "e")?;
        con.wait_for("archive-manager: extracted 2 files to /root/trip", 15)?;
        con.run("cat $HOME/trip/trip/day1/notes.txt $HOME/trip/trip/plan.txt | tr '\\n' ,", "rain,go,", 10)?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(800);
        // The Text Editor: a new file typed, saved, and an edit undone;
        // closing with an unsaved change asks first.
        con.send("text-editor $HOME/notes.txt &\r")?;
        con.wait_for("\"notes.txt\" from pid", 15)?;
        pause(1200);
        type_keys(&mon, "first line\nsecond")?;
        monitor(&mon, &["sendkey ctrl-s"])?;
        con.wait_for("text-editor: saved /root/notes.txt (18 bytes)", 10)?;
        type_keys(&mon, "more")?;
        monitor(&mon, &["sendkey ctrl-z"])?;
        type_keys(&mon, "!")?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(600);
        monitor(&mon, &["sendkey ctrl-s"])?;
        con.wait_for("text-editor: saved /root/notes.txt (19 bytes)", 10)?;
        con.run("cat $HOME/notes.txt | tr '\\n' ,", "first line,second!,", 10)?;
        // Files: into Documents by typing, a copy pasted, moved to the
        // trash and put back, and a file opened in the Text Editor.
        con.run("mkdir -p $HOME/Documents && echo hi > $HOME/Documents/a.txt && echo docs-$((1+1))", "docs-2", 10)?;
        launch(&mon, &mut con, "files", "files")?;
        type_keys(&mon, "Doc\n")?;
        con.wait_for("files: in ~/Documents", 10)?;
        monitor(&mon, &["sendkey ctrl-c"])?;
        monitor(&mon, &["sendkey ctrl-v"])?;
        con.wait_for("files: copied 1 into /root/Documents", 10)?;
        monitor(&mon, &["sendkey delete"])?;
        con.wait_for("files: trashed 1", 10)?;
        con.run("ls $HOME/.local/share/Trash/files", "a (copy).txt", 10)?;
        monitor(&mon, &["sendkey ctrl-z"])?;
        con.wait_for("files: undid Trashed", 10)?;
        con.run("ls $HOME/Documents | tr '\\n' ,", "a (copy).txt,a.txt,", 10)?;
        // Its properties (alt + Enter): the group may write it now.
        monitor(&mon, &["sendkey alt-ret"])?;
        pause(400);
        monitor(&mon, &["sendkey down", "sendkey right", "sendkey spc"])?;
        con.wait_for("files: a.txt is now 664", 10)?;
        monitor(&mon, &["sendkey esc"])?;
        con.run("stat -c %a $HOME/Documents/a.txt", "664", 10)?;
        // The folder bookmarked.
        monitor(&mon, &["sendkey ctrl-d"])?;
        con.wait_for("files: bookmarked ~/Documents", 10)?;
        con.run("cat $HOME/.config/strata/bookmarks", "/root/Documents", 10)?;
        type_keys(&mon, "\n")?;
        con.wait_for("with /bin/text-editor", 10)?;
        con.wait_for("\"a.txt\" from pid", 15)?;
        pause(1000);
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(800);
        // A search of the files' text (Tab in the search field).
        monitor(&mon, &["sendkey ctrl-f"])?;
        pause(300);
        type_keys(&mon, "hi")?;
        monitor(&mon, &["sendkey tab", "sendkey ret"])?;
        con.wait_for("files: found 2 for hi in names and text", 10)?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(800);
        files_to_desktop(&mon, &mut con)?;
        // Calendar: a file imported (opened as Files opens it), an event
        // added from the keyboard, everything exported.
        con.run(
            "cat > $HOME/work.ics <<'EOF'\nBEGIN:VCALENDAR\nX-WR-CALNAME:Work\nBEGIN:VEVENT\nUID:a@x\nDTSTART:20261026T090000Z\n\
             DTEND:20261026T093000Z\nRRULE:FREQ=WEEKLY;COUNT=4\nSUMMARY:Review\nEND:VEVENT\nBEGIN:VEVENT\nUID:b@x\n\
             DTSTART;VALUE=DATE:20261030\nSUMMARY:Away\nEND:VEVENT\nEND:VCALENDAR\nEOF\necho ics-$((1+1))",
            "ics-2",
            10,
        )?;
        con.send("calendar $HOME/work.ics &\r")?;
        con.wait_for("calendar: imported 2 events into Work", 15)?;
        con.wait_for("\"calendar\" from pid", 15)?;
        pause(1200);
        type_keys(&mon, "nDentist\n")?;
        con.wait_for("calendar: saved \"Dentist\"", 10)?;
        monitor(&mon, &["sendkey ctrl-e"])?;
        con.wait_for("calendar: exported", 10)?;
        con.run("grep -c BEGIN:VEVENT $HOME/Documents/Work.ics", "2", 10)?;
        con.run(
            "grep -h SUMMARY $HOME/.local/share/slate/calendars/*.ics | sort | tr -d '\\r' | tr '\\n' ,",
            "SUMMARY:Away,SUMMARY:Dentist,SUMMARY:Review,",
            10,
        )?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(800);
        // Contacts: cards imported, a new one typed in.
        con.run(
            "cat > $HOME/people.vcf <<'EOF'\nBEGIN:VCARD\nVERSION:3.0\nFN:Ada Lovelace\nN:Lovelace;Ada;;;\nTEL:+44 20 7946 0958\n\
             END:VCARD\nBEGIN:VCARD\nVERSION:4.0\nFN:Grace Hopper\nEMAIL:grace@example.com\nEND:VCARD\nEOF\necho vcf-$((1+1))",
            "vcf-2",
            10,
        )?;
        con.send("contacts $HOME/people.vcf &\r")?;
        con.wait_for("contacts: imported 2 cards", 15)?;
        con.wait_for("\"contacts\" from pid", 15)?;
        pause(1200);
        monitor(&mon, &["sendkey ctrl-n"])?;
        type_keys(&mon, "Alan Turing\t+44 161 555 0100\n")?;
        con.wait_for("contacts: saved Alan Turing", 10)?;
        con.run("grep -c BEGIN:VCARD $HOME/.local/share/slate/contacts/contacts.vcf", "3", 10)?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(800);
        // The Web Browser (ADR 0115): a new system has no browser, so it
        // offers Firefox from Flathub, with the Linux runtime to set up
        // first (test images have none); Esc is "not now".
        monitor(&mon, &["sendkey meta_l-spc"])?;
        pause(600);
        type_keys(&mon, "web\n")?;
        con.wait_for("web-browser: offering org.mozilla.firefox (set up: needed, fetch: needed)", 10)?;
        con.wait_for("\"browser\" from pid", 15)?;
        pause(1200);
        monitor(&mon, &["sendkey esc"])?;
        con.wait_for("web-browser: not now", 10)?;
        pause(800);
        // App Center (ADR 0125): with no runtime it offers to set one up.
        // Then, with a catalog of Flathub's form in place (and the
        // runtime's Flatpak stood in for), it lists, searches and opens
        // an app's page.
        monitor(&mon, &["sendkey meta_l-spc"])?;
        pause(600);
        type_keys(&mon, "app center\n")?;
        con.wait_for_all(&["app-center: the Linux runtime isn't set up", "\"app center\" from pid"], 15)?;
        pause(800);
        // Enter sets it up, through the broker; this machine's 512 MiB
        // disk can't hold it, which setup says at once (2026-10-26).
        type_keys(&mon, "\n")?;
        con.wait_for("app-center: the runtime wasn't set up: the Linux runtime needs about 1 GB of free space", 30)?;
        pause(800);
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(600);
        con.run(
            "mkdir -p /var/lib/slate/linux/usr/bin && touch /var/lib/slate/linux/usr/bin/flatpak \
             && D=$HOME/.local/share/flatpak/appstream/flathub/x86_64/active && mkdir -p $D \
             && cat > $D/appstream.xml <<'EOF'\n<components>\n\
             <component type=\"desktop-application\"><id>org.inkscape.Inkscape</id><name>Inkscape</name>\
             <summary>Vector graphics editor</summary><categories><category>Graphics</category></categories>\
             </component>\n<component type=\"desktop-application\"><id>org.gnome.Calculator</id>\
             <name>Calculator</name><summary>Perform calculations</summary></component>\n</components>\nEOF\n\
             echo cat-$((1+1))",
            "cat-2",
            10,
        )?;
        monitor(&mon, &["sendkey meta_l-spc"])?;
        pause(600);
        type_keys(&mon, "app center\n")?;
        con.wait_for_all(&["app-center: 2 apps in the catalog", "\"app center\" from pid"], 20)?;
        pause(1000);
        type_keys(&mon, "vector")?;
        con.wait_for("app-center: 1 apps for \"vector\"", 10)?;
        type_keys(&mon, "\n")?;
        con.wait_for("app-center: the page of org.inkscape.Inkscape", 10)?;
        con.run("grep -c '^org.inkscape.Inkscape' $HOME/.cache/slate/catalog", "1", 10)?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(600);
        con.run("rm -f /var/lib/slate/linux/usr/bin/flatpak", "", 10)?;
        // Help reads the machine before its window opens.
        monitor(&mon, &["sendkey meta_l-spc"])?;
        pause(600);
        type_keys(&mon, "help\n")?;
        con.wait_for("slate-help: kernel: Slate ", 10)?;
        con.wait_for("slate-help: memory: ", 10)?;
        con.wait_for("slate-help: graphics: firmware framebuffer", 10)?;
        con.wait_for("slate-help: display: 1280 × 800", 10)?;
        con.wait_for("\"help\" from pid", 15)?;
        pause(1200);
        type_keys(&mon, "\t\n")?;
        con.wait_for("slate-help: reading \"Getting started with SlateOS\"", 10)?;
        // Its link to the installing guide, then back, and a search.
        pause(600);
        type_keys(&mon, "\t\n")?;
        con.wait_for("slate-help: reading \"Installing SlateOS\"", 10)?;
        monitor(&mon, &["sendkey esc", "sendkey esc"])?;
        pause(400);
        type_keys(&mon, "send the window")?;
        con.wait_for("slate-help: searching for \"send the window\": 1 found", 10)?;
        type_keys(&mon, "\n")?;
        con.wait_for("slate-help: reading \"Installing SlateOS\"", 10)?;
        monitor(&mon, &["sendkey meta_l-shift-e"])?;
        con.wait_for("strata: leaving", 15)?;
        Ok(())
    })();
    if result.is_err() {
        con.drain(500);
    }
    let _ = std::fs::write(target_dir().join("apps-scenario.log"), crate::qemu::strip_ansi(&con.log));
    if let Err(e) = result {
        con.kill();
        return Err(format!("apps scenario: {e} (transcript in target/apps-scenario.log)"));
    }
    con.kill();
    println!(
        "xtask: apps scenario passed (the Calculator's sums in both modes and angle units, the Clock's timer, \
         places and an alarm, the Image Viewer's JPEG and PNG, a zip made and extracted, a file edited and \
         saved, Files' copy, trash and undo, a file dragged from Files onto the desktop, undone there and copied with ctrl, a calendar imported and exported, contacts imported and added, the \
         Web Browser's first-use offer, App Center's offer to set up and a catalog searched, Help's About and a guide, its link and a search; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Base64 (RFC 4648), in lines of 76.
pub fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for (i, c) in data.chunks(3).enumerate() {
        if i > 0 && i % 19 == 0 {
            out.push('\n');
        }
        let n = u32::from(c[0]) << 16 | u32::from(*c.get(1).unwrap_or(&0)) << 8 | u32::from(*c.get(2).unwrap_or(&0));
        for k in 0..4 {
            if k <= c.len() {
                out.push(A[(n >> (18 - 6 * k)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
