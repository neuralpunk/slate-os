# Changelog

What changed in each SlateOS release, newest first.

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
