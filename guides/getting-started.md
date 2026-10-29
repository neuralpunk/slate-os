# Getting started with SlateOS

SlateOS is a small, fast operating system of its own. This guide covers
its desktop, Strata, the apps that come with it, keeping the system up
to date, and running Linux programs. The Help app shows it, with the
other guides, under "guides". Putting SlateOS on a computer is in
[the installation guide](installing.md).

## The desktop

Strata's top bar has the **Applications** menu and the workspaces on
the left, the open windows in the middle, and the mode (Slate mode or
Linux compatibility), the network, the clock and the power button on
the right. Windows float: drag one by its title bar, and resize it from
its edges. The title bar's buttons minimise, maximise and close it, and
clicking a window in the top bar brings it up or minimises it.

- **Applications** opens a menu of the apps by category. Point at a
  category to see its apps, or type to search them all.
- **The power button** (at the far right) locks the screen, logs out,
  restarts or shuts down.
- **The desktop's icons** are what is in your Desktop folder: double
  click one to open it. **Files** is there from the start and opens
  your home folder; delete it from the Desktop folder if you don't want
  it, and it stays gone. Drag icons where you like (they stay there),
  into a folder, or onto a Files window. Choose several with ctrl or
  shift, or by dragging a box around them. The right mouse button
  gives a menu: Open, Rename, Move to Trash, and on the wallpaper New
  Folder and Change Wallpaper.

## Keys

- **super + space** opens the launcher. Type part of an app's name and
  press Enter. With nothing typed, it lists the apps by category, the
  ones you used last first. It also has Lock screen, Log out, Restart,
  Power off, and Roll back to the previous system.
- **super + enter** opens a terminal.
- **alt + tab** brings up the next window.
- **alt + space** reaches the window's title bar buttons: the arrows or
  Tab move between them, Enter presses one, Esc goes back.
- **super + left / right** fills the left or right half of the screen.
  From a half, **super + up / down** fills its top or bottom quarter;
  elsewhere they maximise and minimise. Dragging a window to an edge or
  a corner does the same.
- **super + 1** to **4** switch workspaces; with shift, the window goes
  to that workspace.
- **super + q** closes the focused window.
- **super + l** locks the screen. It also locks by itself after a while
  without use, as Settings › Session says.
- **super + shift + e** leaves Strata for the text console.

The **Shortcuts** app lists these too. Restart, Power off and Roll back
ask for your password first.

## Apps

- **Terminal**: the command line, with SlateOS's own shell and the
  usual tools. Drag to select text (double click for a word, triple
  click for a line); ctrl + shift + c copies and ctrl + shift + v
  pastes, and the middle button (or shift + Insert) pastes what you last
  selected. The right button opens a menu with Copy and Paste. The
  mouse wheel and shift + Page Up / Page Down scroll back. A terminal
  resizes by whole characters and shows its size as you drag.
- **Files**: your files and folders, as a list or a grid with pictures'
  thumbnails. The sidebar has your home folder's usual places, the disks
  and the trash. Typing filters the folder, and ctrl + f searches under
  it. Files opens pictures, archives and text in the apps below.
- **Text Editor**: plain text and code, with undo and redo.
- **Image Viewer**: PNG, JPEG, GIF and BMP pictures, one at a time; the
  left and right arrows go through the folder, and + and - zoom.
- **Archive Manager**: looks into zip, tar, tar.gz, cpio and gzip
  archives and extracts them, and makes zip, tar.gz and tar archives.
- **Calculator**: type sums as you would write them, such as
  `(3+4)/2`, `2^10` or `sin 30`, and press Enter. Tab shows the scientific keys.
- **Clock**: the time in other places, alarms, a timer and a stopwatch.
  Tab moves between them.
- **Calendar**: your events, a month at a time or as an agenda of the
  weeks ahead. It reads and writes iCalendar (.ics) files.
- **Contacts**: an address book. Typing searches it; it imports and
  exports vCard (.vcf) files.
- **Help**: this guide and the others, and **About this system**: what
  the computer is made of. Typing searches the guides; ctrl + c on the
  About page copies its details, for a bug report.
- **System Monitor**: what is running and what it uses, and the
  processors, memory, network and disks. Type to find a program; Delete
  ends it.
- **Disks**: the disks, their partitions and what is on them. It can
  erase a disk, add a partition and format it (FAT32, to use with other
  computers, or SlateFS), each after asking for your password. It never
  touches a disk that is in use.
- **Software Updater**: updates for SlateOS and for your Flatpak apps
  (see "Keeping SlateOS up to date").
- **App Center** and **Web Browser**: apps from Flathub, and Firefox
  (see "The web" and "Apps from Flathub").

## Settings

**Settings** has its sections in a sidebar:

- **Appearance**: the theme (Graphite, Light, Copper Noir or Sediment)
  and the wallpaper: one of the built-in designs, or a picture of your
  own.
- **Accessibility**: high contrast, dimming the windows you aren't
  using, and less motion.
- **Date and time**: the computer's time zone, for everyone on it.
- **Network**: how the computer gets its address (automatically, or a
  fixed address).
- **Bluetooth**: devices nearby, and pairing with them (compare the
  number both show, then press Enter). Bluetooth keyboards, mice and
  headphones can't be used yet.
- **Users**: the people who can log in. Add an account, make it an
  administrator or not, change its password or name, or remove it, and
  choose your own picture for the login and lock screens.
- **Security**: Slate mode and Linux compatibility, the firewall and
  the ports it lets in, the system image and disk encryption.
- **Session**: when the screen locks, and removing the desktop if you
  want the command line only.
- **Displays**: where each display is, its resolution, refresh rate and
  scale, and full graphics on supported AMD Radeon graphics.
- **About**: this computer.

Changes that affect everyone, such as the time zone or the network,
ask for your password first.

## Administering the computer

SlateOS has no root password. The account made when installing is an
administrator: system changes ask for your own password, and in a
terminal, `su -` with your own password gives a root shell.

The system's own files can't be changed, not even by root, except
through the package manager and the updater. That keeps the system
intact, and makes every change one you can undo.

- `quarry search NAME` finds packages, `quarry install NAME` adds one,
  and `quarry remove NAME` takes it away (as root).
- `quarry list` shows what is installed, and `quarry info NAME` tells
  you about a package.

## Keeping SlateOS up to date

The **Software Updater** shows the updates for SlateOS and installs
them as a new version of the system, which starts the next time the
computer starts. The version before is kept: if the new one fails to
start, the computer goes back to it by itself.

- **Roll back to the previous system**, in the launcher, goes back by
  hand, as does `slate-update rollback` (as root). It takes effect at
  the next start.
- `quarry upgrade` (as root) does the same as the Software Updater, and
  `quarry upgrades` lists what it would install.
- `slate-update status` shows the system's versions and which one
  starts next.

## Linux programs

SlateOS runs Linux programs unmodified, kept apart from the rest of
the system, once **Linux compatibility** is on (in Settings ›
Security, or `slate-compat on` as root). Linux programs can't change
SlateOS's system files or see SlateOS's own programs.

For desktop programs such as Firefox, `slate-linux setup` (as root)
makes a Linux runtime: an Alpine Linux system of its own. Its programs
open in their own Strata windows, tagged "linux", and see only your
home folder. `slate-linux upgrade` keeps that runtime up to date; if an
upgrade fails, the runtime is put back as it was, and `slate-linux
rollback` returns to the one from before the last upgrade. The
installation guide's "Linux programs" section has more.

## The web

SlateOS doesn't come with a web browser of its own. Open **Web
Browser** from the launcher the first time and it offers to download
Firefox from Flathub, as Mozilla publishes it there: one click (and
your password, if the Linux runtime isn't set up yet), a few minutes,
and Firefox opens. From then on, Web Browser opens Firefox. It runs in
a sandbox apart from SlateOS, sees only your Downloads folder, and
updates itself in the background; the Software Updater says when, and
can turn that off.

## Apps from Flathub, and AppImages

Apps from Flathub run in a sandbox of their own, in Strata windows like
any other. **App Center** finds them: its categories and search show
Flathub's catalog, and an app's page installs it (for you, or for
everyone on the computer after your password), opens it and removes it.
The first time, it offers to set up what the apps need.

From a terminal, add Flatpak to the Linux runtime once (`slate-linux
setup flatpak`, as root), then, as yourself:

- `slate-flatpak install org.example.App` installs an app; the
  launcher lists it, or `slate-flatpak run org.example.App` starts it.
- `slate-flatpak update` updates them all, keeping each one's version
  before; `slate-flatpak rollback org.example.App` goes back to it.
- `slate-flatpak list`, `slate-flatpak updates` and `slate-flatpak
  remove` do what they say.

`slate-appimage FILE` runs an AppImage. The first one downloads the
runtime AppImages run on, from Flathub.

## What isn't there yet

SlateOS is young, and some things aren't supported yet: Wi-Fi (use a
wired connection or a USB Ethernet adapter), sound, sleep, and
Bluetooth keyboards, mice and headphones. The installation guide's
"What SlateOS runs on" lists the hardware SlateOS works with.
