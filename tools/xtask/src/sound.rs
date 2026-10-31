// SPDX-License-Identifier: MIT OR Apache-2.0

//! The sound scenario (M30 phase 1, ADR 0184): Slate in QEMU with an HD
//! Audio controller and its duplex codec, a second one on QEMU's silent
//! backend (whose recording moves), and a USB audio device. QEMU writes
//! what the first plays to a WAV file (`-audiodev wav`, `none`: never the
//! host's speakers); `/test/sound` checks the ALSA interface on every card
//! and plays known tones, which are then looked for in the files.
//!
//! `cargo xtask sound` (and its `--accept`, part of `cargo xtask accept`)
//! is PipeWire playing sound (M30's criterion): an Alpine workbench with
//! PipeWire, WirePlumber, pipewire-pulse and alsa-utils (made once, cached
//! in target/sound-pw; `--fresh` remakes it; needs the internet) on Slate
//! with an HD Audio card recording to a WAV file. alsa-lib's own tools
//! play (with read-write and mapped access) and set the volume; then
//! PipeWire and WirePlumber start, find the card, run their data thread
//! real-time, and play through PipeWire's own protocol (pw-play) and the
//! PulseAudio one (paplay, which Flatpak apps speak).

use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::desktop::{MOUNT_WORKBENCH, make_workbench};
use crate::qemu::{Console, base_command, monitor};
use crate::{Opts, Result, image, target_dir};

/// Where QEMU writes what a card plays.
fn wav(name: &str) -> PathBuf {
    target_dir().join("sound").join(format!("{name}.wav"))
}

/// QEMU's options for a recording backend: 48 kHz, 16-bit stereo, as the
/// tones are played (no resampling between).
fn audiodev(id: &str, path: &Path) -> String {
    format!(
        "wav,id={id},path={},out.frequency=48000,out.channels=2,out.format=s16,out.buffer-length=10000",
        path.display()
    )
}

pub fn sound_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    // With the test programs (and so Linux compatibility mode).
    let o = &Opts { test_load: true, ..o.clone() };
    let img = image::build(o, "", "slate-sound.img", image::Root::Disk)?;
    std::fs::create_dir_all(target_dir().join("sound")).map_err(|e| e.to_string())?;
    let hda = wav("hda");
    let _ = std::fs::remove_file(&hda);
    let usb = wav("usb");
    let _ = std::fs::remove_file(&usb);
    let mon = target_dir().join("sound-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = base_command(o, &img)?;
    c.arg("-audiodev").arg(audiodev("hda", &hda));
    c.args(["-device", "intel-hda,id=sound0", "-device", "hda-duplex,audiodev=hda,bus=sound0.0"]);
    // A second controller on QEMU's silent backend, whose recording moves
    // (the WAV backend records nothing).
    c.args([
        "-audiodev",
        "none,id=quiet,out.buffer-length=10000,in.buffer-length=10000",
        "-device",
        "intel-hda,id=sound1",
    ]);
    c.args(["-device", "hda-duplex,audiodev=quiet,bus=sound1.0"]);
    c.arg("-audiodev").arg(audiodev("usb", &usb));
    c.args(["-device", "qemu-xhci,id=xhci", "-device", "usb-audio,audiodev=usb,bus=xhci.0,id=usbaudio"]);
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let mut con = Console::start(c)?;
    let result = (|| -> Result {
        con.login()?;
        con.run("cat /proc/asound/cards", "HDA-Intel", 10)?;
        // The USB device comes once the controller has found it.
        con.run(
            "for i in $(seq 100); do grep -q USB-Audio /proc/asound/cards && break; sleep 0.1; done; \
             grep -c USB-Audio /proc/asound/cards",
            "1",
            20,
        )?;
        con.run(
            "ls /dev/snd | tr '\\n' ' '",
            "controlC0 controlC1 controlC2 pcmC0D0c pcmC0D0p pcmC1D0c pcmC1D0p pcmC2D0p",
            10,
        )?;
        con.run("cat /sys/class/sound/pcmC0D0p/uevent | grep DEVTYPE", "DEVTYPE=pcm", 10)?;
        con.run("cat /proc/asound/card0/pcm0p/sub0/status", "closed", 10)?;
        // devd: the nodes are the seat group's; the card's entry is what
        // PipeWire waits for.
        con.run(
            "for i in $(seq 50); do [ -e /run/udev/data/+sound:card0 ] && break; sleep 0.1; done; \
             ls -l /dev/snd/pcmC0D0p | cut -d' ' -f1,3,4",
            "crw-rw---- root seat",
            10,
        )?;
        con.run("cat /run/udev/data/+sound:card0", "E:SOUND_INITIALIZED=1", 10)?;
        let out = con.output("/test/sound check 3 1; echo sound-exit=$?", 180)?;
        let fails: Vec<&String> = out.iter().filter(|l| l.contains("SLATE-TEST: FAIL")).collect();
        if !fails.is_empty() || !out.iter().any(|l| l == "sound-exit=0") {
            return Err(format!("/test/sound check failed:\n{}", out.join("\n")));
        }
        // The volume (ADR 0186): HD Audio's Master and a USB device's PCM
        // Playback set, muted and put back, through slate-sound's command.
        con.run("v0=$(slate-sound volume | sed 's/.*(\\(.*\\)%)/\\1/'); echo was=$v0", "was=", 10)?;
        con.run("slate-sound volume 30", "card 0: 30% (30%)", 10)?;
        con.run("slate-sound volume mute", "card 0: muted (30%)", 10)?;
        con.run("slate-sound volume up", "card 0: 35% (35%)", 10)?;
        con.run("slate-sound volume $v0 && echo restored", "restored", 10)?;
        con.run(
            "u=$(grep USB-Audio /proc/asound/cards | cut -c1-2 | tr -d ' '); u0=$(slate-sound volume -c $u | sed 's/.*(\\(.*\\)%)/\\1/'); slate-sound volume -c $u 50",
            "50% (50%)",
            10,
        )?;
        con.run("slate-sound volume -c $u $u0 && echo usb-back", "usb-back", 10)?;
        con.run("/test/sound play 0 440 1.5", "played 440 Hz", 30)?;
        con.run("/test/sound play 0 660 1.0 mmap", "played 660 Hz", 30)?;
        con.run("/test/sound play $(grep USB-Audio /proc/asound/cards | cut -c1-2) 880 1.5", "played 880 Hz", 30)?;
        // Settings › Sound's self-test: the tune, on the first card.
        con.run("slate-sound test 0", "played the test tune on card 0", 30)?;
        con.run("slate-sound test 7; echo none=$?", "none=3", 10)?;
        // Unplugged while it plays: the program is told (ENODEV), the
        // card goes.
        con.run(
            "/test/sound play $(grep USB-Audio /proc/asound/cards | cut -c1-2) 880 10 > /tmp/unplug.log 2>&1 & \
             echo playing$((1+1))",
            "playing2",
            10,
        )?;
        std::thread::sleep(std::time::Duration::from_millis(1500));
        monitor(&mon, &["device_del usbaudio"])?;
        con.run("wait; cat /tmp/unplug.log", "write: No such device", 20)?;
        con.run("echo gone:$(grep -c USB-Audio /proc/asound/cards)$(ls /dev/snd | grep -c C2)", "gone:00", 10)?;
        con.poweroff()
    })();
    if let Err(e) = result {
        con.kill();
        return Err(format!("sound scenario: {e}"));
    }
    let tones = find_tones(&hda, &[440.0, 660.0])?;
    if tones[0] < 1.2 || tones[1] < 0.8 {
        return Err(format!(
            "sound scenario: {} has {:.2} s of the 440 Hz tone (1.5 s played) and {:.2} s of the 660 Hz one (1.0 s played)",
            hda.display(),
            tones[0],
            tones[1]
        ));
    }
    // The test tune's G major arpeggio and chord (its G5 is to the right;
    // the left channel is read).
    let notes = tone_seconds(&hda, &[392.00, 493.88, 587.33], 0.2)?;
    if notes.iter().any(|&s| s < 0.4) {
        return Err(format!(
            "sound scenario: the test tune's G4, B4 and D5 sound for {:.2}, {:.2} and {:.2} s in {} (0.4 s each wanted)",
            notes[0],
            notes[1],
            notes[2],
            hda.display()
        ));
    }
    let usb_tone = find_tones(&usb, &[880.0])?[0];
    if usb_tone < 1.2 {
        return Err(format!(
            "sound scenario: {} has {usb_tone:.2} s of the 880 Hz tone the USB device played (1.5 s)",
            usb.display()
        ));
    }
    println!(
        "xtask: sound scenario passed (the ALSA interface checked on two HD Audio cards and a USB one; recorded \
         by QEMU: {:.2} s of 440 Hz with WRITEI and {:.2} s of 660 Hz through the mapped buffer on HD Audio, \
         {usb_tone:.2} s of 880 Hz on USB audio, unplugged while playing; the test tune's G4, B4 and D5 \
         for {:.2}, {:.2} and {:.2} s; {:.2}s)",
        tones[0],
        tones[1],
        notes[0],
        notes[1],
        notes[2],
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Alpine packages for the PipeWire check.
const PACKAGES: &str =
    "pipewire wireplumber pipewire-pulse pipewire-tools pipewire-alsa alsa-utils pulseaudio-utils dbus";

/// The tones each player plays (Hz), as they are looked for.
const TONES: [(&str, f64); 4] = [("aplay", 523.0), ("aplay -M", 698.0), ("pw-play", 587.0), ("paplay", 784.0)];

/// Run a command in the workbench as root with PipeWire's environment.
fn in_wb(cmd: &str) -> String {
    format!(
        "chroot /w /bin/sh -c 'export XDG_RUNTIME_DIR=/tmp/xdg DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/xdg/bus; {cmd}'"
    )
}

/// PipeWire on Slate. `strict`: fail unless every check passes (the
/// acceptance); otherwise report what happened.
pub fn pipewire(fresh: bool, strict: bool) -> Result {
    let started = Instant::now();
    let wb = make_workbench("sound-pw", PACKAGES, &[], fresh)?;
    let o = Opts { test_load: true, ..Opts::default() };
    let img = image::build(&o, "slate.compat=on", "slate-pipewire.img", image::Root::Disk)?;
    std::fs::create_dir_all(target_dir().join("sound")).map_err(|e| e.to_string())?;
    let out = wav("pipewire");
    let _ = std::fs::remove_file(&out);
    let mut c = base_command(&o, &img)?;
    crate::qemu::add_disk(&mut c, 0, &wb);
    c.arg("-audiodev").arg(audiodev("hda", &out));
    c.args(["-device", "intel-hda,id=sound0", "-device", "hda-duplex,audiodev=hda,bus=sound0.0"]);
    // A USB audio device plugged in later (into its own recording).
    let usb_out = wav("pipewire-usb");
    let _ = std::fs::remove_file(&usb_out);
    c.arg("-audiodev").arg(audiodev("usb", &usb_out));
    c.args(["-device", "qemu-xhci,id=xhci"]);
    let mon = target_dir().join("sound/pipewire-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let mut con = Console::start(c)?;
    let run = |con: &mut Console, cmd: &str, want: &str, secs: u64| -> Result {
        let r = con.run(cmd, want, secs);
        if r.is_err() && !strict {
            println!("xtask: sound: {cmd}: did not see {want:?}");
            return Ok(());
        }
        r
    };
    let r = (|| -> Result {
        con.login()?;
        con.run(&format!("{MOUNT_WORKBENCH} && echo mounted$((1+1))"), "mounted2", 30)?;
        con.run("cp /test/sound /w/tmp/sound && mkdir -p -m 0700 /w/tmp/xdg && echo copied$((1+1))", "copied2", 10)?;
        for (i, (_, f)) in TONES.iter().enumerate() {
            con.run(&format!("/test/sound wav {f} 2 /w/tmp/t{i}.wav && echo wav{i}$((1+1))"), &format!("wav{i}2"), 10)?;
        }
        // alsa-lib straight to the card.
        run(&mut con, &in_wb("aplay -l"), "card 0: Intel [HDA Intel], device 0", 20)?;
        run(&mut con, &in_wb("amixer -c 0 sset Master 90% unmute"), "Playback", 20)?;
        run(&mut con, &in_wb("aplay -D hw:0 /tmp/t0.wav && echo aplay$((1+1))"), "aplay2", 30)?;
        run(&mut con, &in_wb("aplay -M -D hw:0 /tmp/t1.wav && echo mmap$((1+1))"), "mmap2", 30)?;
        // PipeWire, WirePlumber and the PulseAudio server, as a session
        // starts them.
        con.run(
            &in_wb(
                "dbus-daemon --session --fork --address=$DBUS_SESSION_BUS_ADDRESS;                  pipewire > /tmp/pw.log 2>&1 & sleep 1; wireplumber > /tmp/wp.log 2>&1 &                  pipewire-pulse > /tmp/pp.log 2>&1 & echo started$((1+1))",
            ),
            "started2",
            20,
        )?;
        run(
            &mut con,
            &in_wb("for i in $(seq 40); do wpctl status | grep -q Analog && break; sleep 0.5; done; wpctl status"),
            "Analog Stereo",
            40,
        )?;
        // PipeWire's data thread runs real-time (SCHED_FIFO: policy 1 in
        // /proc/PID/task/TID/stat's 41st field).
        run(
            &mut con,
            &in_wb(
                r#"for p in /proc/[0-9]*; do [ "$(cat $p/comm)" = pipewire ] && pw=$p; done; echo fifo:$(cut -d" " -f41 $pw/task/*/stat | grep -c "^1$")"#,
            ),
            "fifo:1",
            10,
        )?;
        con.run(
            &in_wb(
                r#"for p in /proc/[0-9]*; do [ "$(cat $p/comm)" = pipewire ] && cut -d" " -f2,41 $p/task/*/stat; done"#,
            ),
            "",
            10,
        )?;
        run(&mut con, &in_wb("pw-play /tmp/t2.wav && echo pwplay$((1+1))"), "pwplay2", 30)?;
        run(&mut con, &in_wb("paplay /tmp/t3.wav && echo paplay$((1+1))"), "paplay2", 30)?;
        con.run(&in_wb("tail -n 15 /tmp/pw.log; tail -n 15 /tmp/wp.log; tail -n 5 /tmp/pp.log"), "", 10)?;
        // The person's sound server (ADR 0185): the workbench as the Linux
        // runtime, a person in the seat group, `slate-linux sound` as
        // Strata starts it, and two programs playing at once through it
        // (one opener per card: only a shared server lets both play).
        con.run(
            &in_wb(
                r#"for p in /proc/[0-9]*; do case "$(cat $p/comm)" in pipewire*|wireplumber|dbus-daemon) kill ${p#/proc/};; esac; done; echo stopped$((1+1))"#,
            ),
            "stopped2",
            10,
        )?;
        con.run(
            "useradd -m -d /home/pw -G seat ada && mkdir -p /var/lib/slate/linux && mount -o bind /w /var/lib/slate/linux \
             && mkdir -p -m 0755 /run/user && install -d -m 0700 -o ada -g ada /run/user/$(id -u ada) \
             && /test/sound wav 440 2 /home/pw/a.wav && /test/sound wav 880 2 /home/pw/b.wav && chmod 644 /home/pw/*.wav \
             && echo person$((1+1))",
            "person2",
            20,
        )?;
        con.run(
            "su ada -c 'slate-linux sound' > /tmp/person-sound.log 2>&1 & \
             for i in $(seq 100); do [ -S /run/user/$(id -u ada)/pulse/native ] && break; sleep 0.2; done; \
             cat /tmp/person-sound.log; ls /run/user/$(id -u ada)",
            "native",
            40,
        )?;
        run(
            &mut con,
            "su ada -c 'slate-linux run paplay /home/pw/a.wav' & su ada -c 'slate-linux run paplay /home/pw/b.wav'; \
             wait %2 2>/dev/null; sleep 0.5; echo both$((1+1))",
            "both2",
            40,
        )?;
        // Plugged in now: the kernel announces it, devd re-announces it to
        // libudev's monitors (ADR 0185), and the person's WirePlumber takes
        // the new card.
        monitor(&mon, &["device_add usb-audio,audiodev=usb,bus=xhci.0,id=usbaudio"])?;
        run(
            &mut con,
            "for i in $(seq 40); do su ada -c \"slate-linux run /bin/sh -c 'XDG_RUNTIME_DIR=/run/user/\\$(id -u) wpctl status'\" \
             > /tmp/wp-status 2>&1; grep -qi 'usb' /tmp/wp-status && break; sleep 0.5; done; cat /tmp/wp-status",
            "USB",
            60,
        )?;
        // SLATE_SOUND_TRY=FILE: more commands, one a line, run as given.
        if let Some(file) = std::env::var("SLATE_SOUND_TRY").ok().filter(|f| !f.is_empty()) {
            let cmds = std::fs::read_to_string(&file).map_err(|e| format!("{file}: {e}"))?;
            for cmd in cmds.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
                con.run(cmd, "", 120)?;
            }
        }
        con.run(r"dmesg | grep -ai 'sound\|not supported' | tail -n 20", "", 10)?;
        con.poweroff()
    })();
    std::fs::write(target_dir().join("sound/pipewire.log"), crate::qemu::strip_ansi(&con.log))
        .map_err(|e| e.to_string())?;
    if let Err(e) = r {
        con.kill();
        return Err(format!("sound: {e} (transcript in target/sound/pipewire.log)"));
    }
    let found = find_tones(&out, &TONES.map(|t| t.1))?;
    // The person's two programs, together (each about half the power).
    let person = tone_seconds(&out, &[440.0, 880.0], 0.2)?;
    println!(
        "xtask: sound: the person's sound server: {:.2} s of 440 Hz and {:.2} s of 880 Hz together",
        person[0], person[1]
    );
    if strict && person.iter().any(|&s| s < 1.5) {
        return Err(format!(
            "sound: through the person's sound server, {:.2} s of 440 Hz and {:.2} s of 880 Hz (2 s each played)",
            person[0], person[1]
        ));
    }
    let mut bad = Vec::new();
    for ((who, f), secs) in TONES.iter().zip(&found) {
        println!("xtask: sound: {who}: {secs:.2} s of its {f} Hz tone (2 s played)");
        if *secs < 1.5 {
            bad.push(*who);
        }
    }
    if strict && !bad.is_empty() {
        return Err(format!(
            "sound: too little of {} in {} (transcript in target/sound/pipewire.log)",
            bad.join(", "),
            out.display()
        ));
    }
    println!(
        "xtask: sound: PipeWire run done ({:.0}s); transcript in target/sound/pipewire.log",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// 16-bit stereo samples of a WAV file (the first channel) and the rate.
fn read_wav(path: &Path) -> Result<(Vec<f64>, u32)> {
    let b = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if b.len() < 44 || &b[0..4] != b"RIFF" || &b[8..12] != b"WAVE" {
        return Err(format!("{}: not a WAV file", path.display()));
    }
    // Chunks after the header: "fmt " then "data".
    let mut at = 12;
    let (mut rate, mut channels, mut bits) = (0u32, 0u16, 0u16);
    while at + 8 <= b.len() {
        let id = &b[at..at + 4];
        let len = u32::from_le_bytes([b[at + 4], b[at + 5], b[at + 6], b[at + 7]]) as usize;
        let body = at + 8;
        if id == b"fmt " && body + 16 <= b.len() {
            channels = u16::from_le_bytes([b[body + 2], b[body + 3]]);
            rate = u32::from_le_bytes([b[body + 4], b[body + 5], b[body + 6], b[body + 7]]);
            bits = u16::from_le_bytes([b[body + 14], b[body + 15]]);
        }
        if id == b"data" {
            if bits != 16 || channels == 0 {
                return Err(format!("{}: {bits}-bit, {channels} channels", path.display()));
            }
            // QEMU writes the length when it closes the file; take what is
            // there either way.
            let end = if len == 0 || body + len > b.len() { b.len() } else { body + len };
            let frame = 2 * usize::from(channels);
            let samples = b[body..end]
                .chunks_exact(frame)
                .map(|f| f64::from(i16::from_le_bytes([f[0], f[1]])) / 32768.0)
                .collect();
            return Ok((samples, rate));
        }
        at = body + len + (len & 1);
    }
    Err(format!("{}: no data", path.display()))
}

/// The power of `freq` in `x` (the Goertzel algorithm), normalised to the
/// window's length.
fn goertzel(x: &[f64], freq: f64, rate: f64) -> f64 {
    let w = 2.0 * std::f64::consts::PI * freq / rate;
    let coeff = 2.0 * w.cos();
    let (mut s1, mut s2) = (0.0, 0.0);
    for &v in x {
        let s = v + coeff * s1 - s2;
        s2 = s1;
        s1 = s;
    }
    (s1 * s1 + s2 * s2 - coeff * s1 * s2) / (x.len() as f64 * x.len() as f64)
}

/// How many seconds of each tone `path` holds: 20 ms windows where that
/// frequency carries most of the window's power and the window isn't
/// quiet.
pub fn find_tones(path: &Path, freqs: &[f64]) -> Result<Vec<f64>> {
    tone_seconds(path, freqs, 0.4)
}

/// As `find_tones`, for notes that sound together (a tune): windows where
/// the frequency carries `share` of the power.
fn tone_seconds(path: &Path, freqs: &[f64], share: f64) -> Result<Vec<f64>> {
    let (x, rate) = read_wav(path)?;
    let win = (rate / 50) as usize;
    let mut secs = vec![0.0; freqs.len()];
    for w in x.chunks_exact(win) {
        let energy: f64 = w.iter().map(|v| v * v).sum::<f64>() / w.len() as f64;
        if energy < 1e-4 {
            continue;
        }
        for (i, &f) in freqs.iter().enumerate() {
            // A pure sine's power here is amplitude^2 / 4; its energy
            // amplitude^2 / 2.
            if goertzel(w, f, f64::from(rate)) > share * energy {
                secs[i] += win as f64 / f64::from(rate);
            }
        }
    }
    Ok(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tones_are_found_in_a_wav_file() {
        let rate = 48000u32;
        let mut data = Vec::new();
        // 0.5 s of silence, 1 s of 440 Hz, 0.5 s of 660 Hz.
        for i in 0..(rate * 2) {
            let t = f64::from(i) / f64::from(rate);
            let v = if t < 0.5 {
                0.0
            } else if t < 1.5 {
                (2.0 * std::f64::consts::PI * 440.0 * t).sin() * 0.3
            } else {
                (2.0 * std::f64::consts::PI * 660.0 * t).sin() * 0.3
            };
            let s = ((v * 32767.0) as i16).to_le_bytes();
            data.extend_from_slice(&s);
            data.extend_from_slice(&s);
        }
        let mut b = Vec::new();
        b.extend_from_slice(b"RIFF");
        b.extend_from_slice(&(36 + data.len() as u32).to_le_bytes());
        b.extend_from_slice(b"WAVEfmt ");
        b.extend_from_slice(&16u32.to_le_bytes());
        b.extend_from_slice(&[1, 0, 2, 0]);
        b.extend_from_slice(&rate.to_le_bytes());
        b.extend_from_slice(&(rate * 4).to_le_bytes());
        b.extend_from_slice(&[4, 0, 16, 0]);
        b.extend_from_slice(b"data");
        b.extend_from_slice(&(data.len() as u32).to_le_bytes());
        b.extend_from_slice(&data);
        let dir = std::env::temp_dir().join(format!("slate-wav-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.wav");
        std::fs::write(&p, &b).unwrap();
        let t = find_tones(&p, &[440.0, 660.0, 1000.0]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!((0.95..=1.05).contains(&t[0]), "{t:?}");
        assert!((0.45..=0.55).contains(&t[1]), "{t:?}");
        assert_eq!(t[2], 0.0);
    }
}
