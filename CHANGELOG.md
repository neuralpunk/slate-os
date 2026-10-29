# Changelog

What changed in each SlateOS release, newest first.

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
