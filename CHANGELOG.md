# Changelog

What changed in each SlateOS release, newest first.

## 0.1.3 (2026-10-30)

### Linux software from source, in a Linux system of your own

- **Build Linux command-line software from source.** Each person can
  have a real Linux system of their own: Arch Linux, with GCC, make,
  CMake, Meson, pkg-config and the rest of its build tools. It runs
  apart from SlateOS, in a box. `slate-box setup` makes it. Its download
  is checked against Arch Linux's own release key by SlateOS's own
  OpenPGP code before anything is unpacked.
- **It feels like part of SlateOS.** In SlateOS's terminal you use the
  Linux system's commands as you would any other: `make`, `gcc` and
  `pacman` simply work, in the folder you are in. In a folder with
  source code (a `configure`, `Makefile`, `CMakeLists.txt` and so on),
  `./configure` asks once whether to build that project with Linux
  tools, then remembers the answer. `sudo make install` installs into
  the Linux system, not into SlateOS. Programs you build there become
  commands ("hello is now a command") and start in a few milliseconds.
  SlateOS's own commands always come first. `slate-box here` and
  `slate-box not-here` change a folder's choice.
- **You always know it's Linux.** Linux programs show up as such: the
  terminal's title and the window's tag say "linux", and the box's
  prompt says `[box linux]`. A Linux program can never stand in for one
  of SlateOS's.
- **Kept apart from SlateOS.** Inside the box, its root has no power
  over SlateOS. Each box has its own users and IDs, mapped to IDs that
  no account on SlateOS has. Each box also has its own processes, mounts
  and terminals. It sees your files only in the folder you are working
  in, it can't see SlateOS's processes or write SlateOS's system, and
  its network can be turned off (`slate-box network`). When a box's
  program is refused something, SlateOS notes it in its log, so a
  misbehaving build script shows up.
- **Every install has a receipt.** Each `sudo make install` or
  `pacman -S` in the box records exactly which files it added, changed
  or removed. `slate-box installs` lists the receipts. `slate-box undo`
  takes one install back, and refuses when a later install depends on
  the same files. `slate-box rollback` returns the whole Linux system to
  how it was before an install.
- **A sealed channel, and nothing else.** The box talks to SlateOS
  over one private channel per session, encrypted with a fresh key each
  time (ChaCha20-Poly1305). It accepts only a few named requests, such
  as making an install receipt. A message that has been forged,
  replayed, or comes from another session is refused and logged.
- **Several boxes, if you like.** `slate-box create NAME` makes
  another. `share` and `unshare` choose which of your folders a box
  sees, `show` says what it may do, and `enter` opens its shell when you
  want to be inside it.
- **See and free the space it uses.** Settings has a new page, Linux
  boxes. It shows the space each box and each downloaded base system
  takes (counting only what each holds of its own), and warns when the
  disk is getting full. It can clear package caches and remove a box or
  a base. From the terminal, `slate-box list` and `slate-box clean` do
  the same.

### Desktop and Terminal

- **Tabs in the Terminal.** The **+** after the tabs, ctrl + t, or
  **New tab** on the right button's menu opens a tab, in the folder you
  are in, with a shell of its own. A tab's **×** (or the middle button
  on it) and ctrl + shift + w close it, and the window closes with its
  last tab. ctrl + Page Up / Page Down and ctrl + tab move between tabs,
  and a dot marks a tab that printed something while you were in
  another. Full-screen programs keep ctrl + t for themselves (nano's,
  for one): ctrl + shift + t opens a tab there.
- **The Super key opens the Applications menu.** Pressing the Super
  (Windows) key on its own opens the Applications menu at the top left,
  and pressing it again closes it. Super with another key (super +
  space, super + enter and the rest) works as before. The Shortcuts
  window lists it.

### Accounts

- **"Can use the desktop"** in Settings › Users: a switch on each other
  account's page, beside Administrator, says whether the desktop starts
  when they log in, or only the command line. Accounts made in Settings
  can now use the desktop (before, they couldn't start it), and someone
  who may not is told where an administrator can allow it.

### Linux apps: faster, themed, native-looking

- **Windows start faster.** A Linux app's window now appears in about
  a tenth of a second once it is warmed up, and the first one after
  logging in is nearly as quick: SlateOS reads what Linux apps need into
  memory a few seconds after you log in, and finds each app's display
  the moment it is ready instead of looking for it every tenth of a
  second.
- **Less copying.** A Linux app's frames go straight into the memory
  SlateOS's desktop draws from, so the bridge between them no longer
  copies every frame (several times over, before); only what changed is
  redrawn, and the app is asked for its next frame when the last one is
  on the screen.
- **Apps follow your theme.** GTK, libadwaita and Qt apps from Flathub
  (GNOME's apps among them) and Firefox now follow SlateOS's light or
  dark theme, its accent colour and high contrast, and use its fonts
  (Host Grotesk and DM Mono). Change the theme in Settings and running
  apps change with it.
- **Their own icons and names.** Linux apps show their own icon in the
  Applications launcher and on their windows' title bars, and their
  windows carry the app's name ("Calculator", not its ID). They keep
  their "linux" tag.
- **GNOME's apps start.** Apps built on GNOME's Flatpak runtime (such
  as GNOME's Calculator) failed to start; they now run.

### Web Browser and App Center

- **Firefox in one click, with real progress.** On a computer that has
  never run a Linux app, "Get Firefox" sets everything up and opens it
  with nothing more to answer than the one approval. The window says
  which step it is on and how far it has got as a percentage ("Fetching
  Firefox from Flathub (2 of 2): 42%"), with what is being downloaded
  and how much of it there is, and a bar that fills.
- **App Center** shows the same: how far an install has got, and what
  it is fetching.
- **`slate-flatpak`** installs and updates now say how far they are as
  they go (`slate-flatpak: 42% of 1.1 GB: org.mozilla.firefox (7 of 7)`).

### Under the hood

- Each Linux app gets a session bus of its own, with a settings service
  of SlateOS's own on it (the desktop portal's Settings), which is how
  apps learn the theme. Other portals report that they aren't there, so
  apps keep their own file choosers.
- The Linux runtime's setup now includes SlateOS's fonts and makes the
  font cache ahead of time.
- The vDSO (the page every process uses to read the clock quickly) is
  now laid out as one read-only segment, as C libraries expect; glibc's
  static programs crashed on it before.
- `slate-linux run` no longer covers the runtime with the system's own
  files when run with a home directory of `/`.
- For Linux programs: `splice`, `fchmodat2` and `pivot_root` now work.
  `statx` reports mount IDs, which systemd's tools need. devpts can be
  mounted as a new instance with its own terminals (sudo needs one in a
  container). A pipe now belongs to whoever made it, so `/dev/fd`
  paths to pipes open as they should. A rare lock-order deadlock in
  tmpfs, under parallel builds, is fixed.
- SlateFS can say how much of a subvolume is its own and how much it
  shares with snapshots, which is what Settings shows.
- For SlateOS's own programs, three new native system calls: one marks
  a process as part of a box (shown as `Box:` in `/proc/PID/status`),
  plus `unshare` and `pivot_root`.
- For developers: `cargo xtask flatpak --measure` times a Linux app's
  start-up, frames, keys and installs against budgets; `--browser` and
  `--themed` check Firefox in one click and a themed GTK app.
- For developers: `cargo xtask box` keeps an Arch Linux workbench, with
  a caching mirror so repeated runs don't download again. Its
  `--accept` builds GNU hello, nano, htop and four more source packages
  in a box, from their own release tarballs. A new test scenario drives
  boxes end to end, including a hostile Makefile that tries to break
  out and is refused.

## 0.1.2 (2026-10-29)

### Network: Intel's I225 and I226

- **A new wired network driver.** Intel's I225 and I226 2.5 Gigabit
  Ethernet controllers (I225-V, I225-LM, I226-V, I226-LM and their
  relatives, the I220-V and I221-V), the wired port on many recent
  desktop and laptop boards, now work. They are driven like Intel's
  I210 family, with one receive and one transmit queue.
- **Fast.** Received frames raise interrupts, moderated as Intel's own
  driver sets them, so they no longer wait for a timer; downloads of
  about 100 MB/s have been seen.
- **When a card stays quiet.** A network card that receives frames but
  raises no interrupts for them is noticed and polled every 10 ms
  instead, and says so in `dmesg`. For its first minute an I225/I226
  logs its own counters there (frames, misses, interrupts), and a card
  that can't be started says why (`dmesg | grep igc`).

### Hardware

- **Devices behind bridges.** SlateOS now turns on memory access in
  every PCI bridge between a device and the processor, not only in the
  device itself. Firmware often leaves it off on ports it didn't boot
  from, and a card behind one could neither reach memory nor raise
  interrupts.
- **Devices in low-power states.** PCI devices that firmware left
  powered down are woken before use, with their settings put back.

### Web Browser and Linux apps

- **Firefox on first use.** Setting up the Linux runtime (the first
  time the Web Browser or App Center needs it) runs one setup at a
  time: a second one started while the first is under way waits for it
  instead of failing.
- **Clear answers.** `web-browser --get` shows the setup's progress
  while it waits; a failed setup quotes the error of the program that
  failed, and the runtime is checked afterwards, naming exactly what is
  missing if something is.
- **Permissions fixed.** On a computer with a Bluetooth controller, the
  Bluetooth service could create `/var/lib/slate` readable by root
  only, shutting other users (such as "Try SlateOS"'s live user) out of
  the Linux runtime. It is now created readable by everyone, and one
  made earlier is opened up.

### Command line

- **`chattr` and `lsattr`.** SlateOS's own versions of the tools that
  show and change a file's attributes. UEFI variables that firmware
  needs are immutable, and `chattr -i` now unlocks one without a Linux
  program; `lsattr` shows which are locked.
- **Checksums.** `md5sum`, `sha256sum` and the rest (and `cksum`)
  handle file names with backslashes and newlines the way GNU's tools
  do, so their lists can be checked by either. They also gain `-z`
  (lines ending in NUL) and `--ignore-missing`. With `-c` they now say
  which files couldn't be read and which lines weren't checksum lines.
- **top.** Running tasks show in bold. `x` highlights the sort column,
  `b` switches highlights between bold and reverse video, and `z`
  colours the task list as well as the summary. `Z` opens a screen for
  choosing each window's colours. `<` and `>` move the sort to the
  next column. The arrow keys, PgUp, PgDn, Home and End scroll the task
  list and the columns (`C` shows where you are). The process tree
  (`V`) now also works while threads are shown. Each window's look is
  saved with `W`.

### Desktop

- **Settings › Displays in "Try SlateOS"**: the Graphics row explains
  that full graphics is chosen during the install, rather than offering
  a change that would only take effect at a next start.
- When turning on full graphics fails, the message now gives quarry's
  own reason.

## 0.1.1 (2026-10-29)

### Bluetooth: mice that just work

- **Bluetooth Low Energy.** Mice, keyboards and other input devices that
  use Bluetooth Low Energy now pair, connect and come back by
  themselves: LE Secure Connections (or legacy pairing, for older
  devices), and HID over GATT for their input. Pairings are kept, and a
  paired device reconnects whenever it is in range.
- **A mouse pairs by itself.** Switch a Bluetooth mouse into pairing
  mode and SlateOS pairs it and puts the pointer on screen, in an
  installed system and in "Try SlateOS" alike, whatever else is plugged
  in, so a computer whose only mouse is a Bluetooth one can be used
  right away. A device paired this way can move and click but never
  type; pair it from Settings or `slate-bt` to give it everything it
  has. `/etc/slate/bluetooth` chooses `autopair=always` (the default),
  `auto` (only while no other pointer is connected) or `never`.
- **Pairings survive the install.** Devices paired in the live system
  keep working in the installed one, without pairing again.
- **MediaTek controllers.** The Bluetooth halves of MediaTek's MT7961,
  MT7922, MT7902 and MT7925 Wi-Fi/Bluetooth cards (common in AMD
  desktops and laptops) now work: SlateOS loads their firmware when they
  start. The firmware is MediaTek's (the `slate-firmware-bt` package,
  under MediaTek's licence); it is on the install media and installed
  automatically on computers that have such a card, and can be removed
  with `quarry`.
- **Input devices from user space.** The kernel's `/dev/slate-hid`
  turns a report descriptor and its reports into input devices, the
  same way USB keyboards and mice are handled; the Bluetooth daemon
  uses it. USB keyboards and mice now disappear properly when unplugged.

### Games

SlateOS's first games, under Games in the Applications menu.

- **Solitaire**: Klondike, the classic patience game. Drag and drop or
  play with the keys, draw one or draw three, unlimited undo, a move
  count and a clock, and the game finishes itself once every card is
  face up. The cards are SlateOS's own design, their backs a colourful
  landscape of rock strata.
- **Mines**: clear the field without opening a mine. Small, medium and
  large boards with each one's best time kept, flags with the right
  button, and the first square you open is never a mine.

### Files

- Several copies can run at once; each counts its size in the
  background, so the window never waits.
- Searching (names, or names and text) and a folder's size in its
  properties are worked out in the background, results shown as they
  are found.
- **Power off** for USB disks: the right button on a disk in the
  sidebar unmounts it, stops it and lets it go, ready to unplug
  (`slate-disk poweroff` from the command line).
- A disk's shared trash folder (`.Trash`, as other systems make it) is
  used when the disk has one.
- Text files show their first lines as thumbnails in the grid view.

### Desktop

- The Copper Noir and Sediment themes now set their dates and
  Sediment's window titles in their serif typefaces, Instrument Serif
  and Fraunces (both under the SIL Open Font License).
- Apps can declare their colour in the Sediment theme (`accent=` in
  their `.app` file, from ochre, terracotta, sage, olive and slate).
- New icons for cards and flags; the Games category uses the cards.

## 0.1.0 (2026-10-29)

The first public release.
