# Installing SlateOS

This guide takes you from a USB stick to a working SlateOS: making the
install medium, setting up the PC's firmware, trying SlateOS from the
stick, installing it, and the first start. It ends with what to do when
something goes wrong, and with trying SlateOS in a virtual machine.

**Installing erases the disk you choose, unless you install SlateOS
beside what is already on it** (see "Installing beside another system").
Back up anything you want to keep first.

## What you need

- **A 64-bit PC** (Intel or AMD) that starts in UEFI mode or in legacy
  BIOS mode. A disk of 2 GB or more to install on.
- **A USB stick** of 512 MB or more. Everything on it is erased.
- **A screen, a keyboard and a mouse** for the install. A keyboard
  that's plugged straight into the PC works best; one with a built-in
  USB hub is fine, but a separate USB 3 hub may not work. Once SlateOS
  is installed, you can also use the PC without a screen, over SSH.
- **A wired network connection**, if you want to reach the internet.
  On most home networks (anything with DHCP, which most routers
  provide) there is nothing to set up. For networks with fixed
  addresses, see "Network settings".

## What SlateOS runs on

SlateOS has its own drivers, so it works with some hardware and not yet
with other hardware. Before you install, check that your PC has what it
needs:

| Hardware | What works |
|---|---|
| Disks | NVMe drives, SATA drives (with the firmware's SATA mode set to AHCI) and USB drives |
| Wired network | Intel I210, I211 and 82576 network cards, and USB Ethernet adapters of the standard (CDC Ethernet) kind |
| Wi-Fi | Not supported yet. Use a wired connection or a USB Ethernet adapter |
| Keyboard and mouse | USB (through the PC's USB 3 controller) and PS/2 |
| Graphics | Any graphics card, at the resolution the PC starts with. Some AMD Radeon graphics can also run at your monitor's own resolution (see "Full graphics on AMD Radeon") |
| Bluetooth | USB Bluetooth adapters can pair with devices, but Bluetooth keyboards, mice and headphones can't be used yet |
| Sound | Not supported yet |
| Sleep | Not supported yet. A short press of the power button shuts the PC down cleanly |

Many PCs have built-in Ethernet from Realtek or another maker that
SlateOS doesn't drive yet. On those, a USB Ethernet adapter gets you
online.

## Make the install medium

The install medium is a disk image, `slate-usb.img`. It's built from
SlateOS's source code: in a checkout of the repository, run

```sh
make usb
```

and the image lands in `target/slate-usb.img`. (`make iso` makes
`target/slate.iso` instead, for DVDs and virtual machines, and `make`
makes both. `make deps` says which tools the build needs.)

The image is written to the stick raw, byte for byte, over the whole
stick: copying the file onto the stick doesn't work.

### With dd, on Linux

1. Run `lsblk`, plug the stick in, and run `lsblk` again. The disk that
   appeared (for example `/dev/sdb`) is the stick. Check that its size
   matches your stick.
2. Write the image, replacing `sdX` with the stick's name. Use the
   whole disk (`sdb`), not a partition on it (`sdb1`):

```sh
sudo dd if=target/slate-usb.img of=/dev/sdX \
    bs=4M status=progress conv=fsync
```

### With GNOME Disks

Choose the stick in the list, open the menu (⋮), choose **Restore Disk
Image…** and pick `slate-usb.img`.

On other systems, any tool that writes a disk image to a USB stick byte
for byte does the job.

## Set up the PC's firmware

You only need to do this once. Plug in the stick, turn the PC on, and
open the firmware's setup. The key for it depends on the maker: it is
often **Del**, **F2**, **F10** or **Esc**, and the PC usually shows it
for a moment while it starts. Then check these settings:

- **Secure Boot: off.** SlateOS's bootloader isn't signed for Secure
  Boot, so the PC won't start it while Secure Boot is on.
- **Boot mode: UEFI** is best. Legacy BIOS (often called CSM) works
  too, and the installed system then starts the same way. Installing
  beside another system needs UEFI.
- **SATA mode: AHCI**, if the PC has SATA drives. In RAID or "Intel RST"
  mode SlateOS can't see the drives. (If Windows is installed on the
  PC, switching this setting can stop Windows from starting; leave it
  if your disk is an NVMe drive.)

Save the settings and leave the setup.

## Start from the USB stick

While the PC starts, press the key for its **boot menu**. Like the
setup key, it depends on the maker: often **F12**, **F11**, **F8** or
**Esc**. Choose the USB stick. Many PCs list it twice: the entry that
starts with "UEFI:" starts it in UEFI mode (the one to choose), and the
other starts it in legacy BIOS mode.

SlateOS's boot menu shows **Install Slate** for three seconds, then
starts it. The second entry, **Install Slate (text mode)**, starts the
text installer instead: choose it with the arrow keys and press Enter.

After a few seconds the installer's welcome screen appears. If the PC's
screen can't show it, the text installer starts instead.

## Try SlateOS without installing

On the welcome screen, **Try SlateOS** starts the Strata desktop straight
from the stick, so you can look around first. It runs in memory as the
user `live`, with no password, and nothing on the computer's disks
changes. Whatever you do there is gone when the computer restarts.

When you're ready, **Install SlateOS** on the top bar (or in the
launcher, super + space) brings the installer back.

## Install

The installer works with the mouse or the keyboard: Tab moves between
controls, the arrow keys choose within a list, Enter goes on, and Esc
asks whether you want to quit. Quitting before the installation starts
changes nothing on your disks. The button at the bottom left of the
welcome screen offers **Larger text** and **High contrast**.

1. **Welcome.** Choose your language, English (United States) or
   English (United Kingdom), and press **Install SlateOS**.
2. **Time zone and keyboard.** Choose your time zone and keyboard
   layout. Type part of a name to narrow the lists (a city like
   `Berlin`, a country like `Norway`, a layout like `German`), then
   choose with the arrow keys or the mouse. Each time zone shows its
   country's code. Both start from what your language suggests, or from
   the time zone your network names, if it names one. The layout takes
   effect at once, so try it in the keyboard field before you type your
   password. On layouts with accent keys (German's ´ and ^, US
   International's ' and "), the accent goes on the next letter you
   type; for the accent on its own, press it and then Space.
3. **Disk.** Choose the disk to install on. Each disk shows its size,
   its kind and how many partitions it has. The USB stick you started
   from is never offered. A disk without partitions is used whole. On a
   disk that already has partitions, the installer next asks how to
   install on it (see "Installing beside another system").
   **Encrypt disk** (on unless you turn it off) locks SlateOS's part of
   the disk with your account's password: the PC asks for it every time
   it starts, and nobody can read the disk without it. If you forget the
   password and have no recovery key, the data can't be recovered.
4. **Mode.** **Slate mode** (the default) is the secure choice: a
   signed, read-only system, where programs get only the permissions
   they're given. **Linux compatibility** also lets Linux programs run,
   kept apart from the rest of the system. You can switch at any time
   later, in Settings › Security or with `slate-compat on` and
   `slate-compat off`; Web Browser turns it on when it needs it, after
   asking for your password.
5. **Desktop.** The **Strata desktop** (the default) or **Command line
   only**. With Strata, the PC starts to a graphical login screen. Either
   way, the full command line is there. On a PC with supported AMD
   Radeon graphics, this step asks one more question (see "Full graphics
   on AMD Radeon").
6. **Network.** **Automatic (DHCP)**, right for most networks, or a
   **Fixed address**: the address with its prefix length (for example
   `192.168.1.20/24`), the gateway and the name servers. Every network
   card gets these settings, and you can change them later in Settings.
7. **Account.** Your name, a username, the computer's name and a
   password. SlateOS has no root password: you log in as yourself, and
   approve system changes with your own password.

Press **Install SlateOS**. Installing takes about a minute. When the
installer says **SlateOS is ready**, remove the USB stick and press
**Restart now**.

If the PC doesn't find the installed system by itself, choose it once
in the firmware's boot menu: it is the entry called "Slate" (or "UEFI
OS", or the disk's name).

### Installing beside another system

When the disk you choose already has partitions (Windows, Linux, or
another SlateOS), the installer shows what is on it and offers three
ways to go on:

- **Install beside it.** SlateOS goes in the disk's largest free space,
  and nothing already on the disk changes. It needs 2.1 GB of free
  space, or 2.7 GB if it can't share the disk's existing EFI System
  Partition. To make room, shrink the other system's partition with
  that system's own tools first (in Windows: Disk Management, then
  "Shrink Volume").
- **Erase disk and install SlateOS.** Everything on the disk is lost,
  as on an empty disk.
- **Choose partitions yourself.** The disk's partitions and free spaces
  are listed. Delete the partitions you no longer want (nothing is
  deleted until the installation starts, and **Undo deletions** brings
  them back), then choose a free space and how many GB SlateOS gets
  (leave it empty for all of it).

Installing beside another system needs a disk with a GPT partition
table, and the installer started in UEFI mode (the "UEFI:" entry in the
firmware's boot menu). The installer tells you when one of these is
missing.

Afterwards, when the PC starts, SlateOS's boot menu lists the other
system after SlateOS. Choose it with the arrow keys and press Enter
within three seconds. The firmware's own boot menu still lists every
system too.

### Full graphics on AMD Radeon

SlateOS runs every graphics card with its own code, at the resolution
the PC starts with. On a PC with AMD Radeon graphics that SlateOS's
driver supports (today, the graphics built into some recent AMD Ryzen
processors), the Desktop step also offers **full graphics**: your
monitor at its own resolution, with smoother updates. For that,
SlateOS's driver loads AMD's firmware, software from AMD that runs on
the graphics card itself.

- **SlateOS only** (the default) keeps the resolution the PC starts
  with.
- **Full graphics** adds AMD's firmware.

If you choose full graphics, the first start asks **Keep full
graphics?** and counts down 20 seconds. Choose **Keep** if the screen
looks right. If you choose **Revert**, press Esc, or don't answer in
time (for example because the screen shows nothing), SlateOS goes back
to its standard graphics and restarts by itself.

At any later time, the boot menu's **Slate (standard graphics)** entry
starts SlateOS without full graphics, and **Settings › Displays**
turns full graphics off (or on) for good.

### The text installer

The text installer asks the same questions, one after another: the
disk, how to install on it (type `erase` to confirm erasing it, or
`delete` to confirm deleting partitions), the keyboard layout, the time
zone, your account, encryption, the desktop, Linux compatibility, full
graphics (on a PC with supported AMD graphics) and the network. In the
list of partitions, type a partition's number to delete it, or a free
space's letter to install there. For the time zone, type part of a
name, or press Enter for the one it suggests (your network's, or the
keyboard layout's country's).

At the disk question, typing `shell` gives a command line, where
`dmesg` shows what the system found, and typing `try` lets you try
SlateOS at a command line as the user `live`; the installer comes back
when you leave it.

## The first start

### Unlocking the disk

If you encrypted the disk, the PC first shows **Unlock this disk**. Type
your password (a dot shows for each character) and press Enter. If the
password is wrong, it says so and you can try again. On a PC without a
working screen, the console asks for the password instead, and nothing
shows as you type.

### Logging in

With the Strata desktop, the **login screen** comes next: choose
yourself in the list (with the arrow keys or the mouse), type your
password and press Enter. **Restart** and **Power off** are at the
bottom right. Logging out of Strata brings the login screen back. If
the login screen ever doesn't work, press `e` in SlateOS's boot menu
and add `slate.login=text` to the kernel command line for a text login
instead.

With the command line only, the console shows a login prompt and the
PC's network address:

```
Network address: 192.168.1.50
```

To get a root shell, run `su -` and type your own password.

### The desktop's keys

| Keys | What they do |
|---|---|
| super | the Applications menu (press it again to close it) |
| super + enter | open a terminal |
| super + space | the launcher: apps, and Lock screen, Log out, Restart, Power off and Roll back |
| alt + tab | the next window |
| alt + space | the window's title bar buttons (arrows or Tab move, Enter presses, Esc goes back) |
| super + up / down | maximise (or restore) / minimise the window |
| super + left / right | put the window on the left or right half |
| super + 1–4 | switch workspace (with shift: send the window there) |
| super + l | lock the screen |
| super + q | close the focused window |
| super + shift + e | leave Strata for the text console |

Restart, Power off and Roll back ask for your password first. The
[getting started guide](getting-started.md) has more on the desktop
and its apps.

### Logging in from another computer

SlateOS has an SSH server, and it is on from the start. From another
computer on the same network:

```sh
ssh ada@192.168.1.50
```

Use your own username and the address the PC's console shows. The
first time, SSH asks you to confirm the PC's host key; its
fingerprint is printed on the PC's console when the SSH server starts
(`sshd: listening on port 22, host key SHA256:...`).

To log in with a key instead of your password, copy your public key to
the PC once:

```sh
ssh ada@192.168.1.50 'mkdir -p .ssh &&
  cat >> .ssh/authorized_keys' < ~/.ssh/id_ed25519.pub
```

## Your encrypted disk

The disk's password is your account's password: when you change your
password with `passwd`, the disk's password changes with it.

Make a **recovery key** as well, and write it down somewhere safe. It
unlocks the disk if the password is ever forgotten. As root (`su -`):

```sh
slate-crypt add-recovery-key root   # prints the key
slate-crypt status root             # the disk's key slots
```

Type the recovery key wherever the password is asked for; capital
letters, dashes and spaces don't matter. `slate-crypt` also adds and
removes passwords, checks which slot a password opens, repairs a
damaged header from its backup copy (`repair`), and creates and opens
other encrypted partitions (`format`, `open`, `close`).

## Starting another system

When SlateOS is installed beside another system, SlateOS's boot menu
lists both; choose one within three seconds of the menu appearing. From
SlateOS you can also pick the system for the next start only. As root:

```sh
slate-update next                         # the menu's entries
slate-update next 'Windows Boot Manager'  # start it next time
```

## Linux programs

Graphical Linux programs, such as Firefox, run in a **Linux runtime**: an
Alpine Linux system kept in `/var/lib/slate/linux`, apart from SlateOS.
Its programs run in a sandbox of their own: they can't change
SlateOS's system files or touch SlateOS's own programs, and of your
files they see only your home folder. Their windows carry a **linux**
tag.

To set up the runtime, connect to the internet and, as root (`su -`),
turn on Linux compatibility and run `slate-linux setup`:

```sh
slate-compat on
slate-linux setup
```

It downloads Alpine Linux's small base system (about 4 MB), checks it
against the checksum SlateOS knows, unpacks it, and installs Sway,
Xwayland, Firefox and a font with Alpine's package manager (a few
hundred MB). To install other Alpine packages instead, name them
(`slate-linux setup foot`); run it again later to add more.
`--mirror URL` uses another Alpine mirror.

The launcher then lists the runtime's programs, or you can start one
from a terminal with `slate-linux-app firefox`. Programs without a
window run in the terminal with `slate-linux run PROGRAM`. Copy and
paste work between Linux programs and SlateOS's own.

`slate-linux upgrade` brings the runtime up to date. If an upgrade
fails, the runtime is put back as it was, and `slate-linux rollback`
returns to the runtime from before the last upgrade.

### The web browser

SlateOS doesn't include a web browser of its own. The first time you
open **Web Browser** in the launcher (or run `web-browser` in a
terminal), it offers to download Firefox from Flathub, as Mozilla
publishes it there, after checking that Flathub's signing key is the
one SlateOS trusts. If Linux compatibility is off or the Linux runtime
isn't set up yet, it sets them up first, which asks for your password.

- `web-browser --get` does the same from a terminal.
- `web-browser --use com.example.Browser` makes another browser you
  installed from Flathub the one Web Browser opens.
- If the browser doesn't appear, look in `~/.cache/slate/browser.log`
  for what it said.

### Flatpak apps and AppImages

**App Center** in the launcher browses and searches Flathub's catalog,
and installs, opens and removes apps. The first time, it offers to set
up Flatpak in the Linux runtime (or, as root, run `slate-linux setup
flatpak`). Apps are your own, kept in your home folder, so installing
one needs no password. Each app runs in Flatpak's sandbox, with only
the access its makers asked for.

From a terminal:

```sh
slate-flatpak install org.gnome.Calculator
slate-flatpak run org.gnome.Calculator
slate-flatpak updates     # what is newer on Flathub
slate-flatpak update      # update them all
slate-flatpak rollback org.gnome.Calculator
slate-flatpak list
slate-flatpak remove org.gnome.Calculator
```

`slate-flatpak update` keeps each app's previous version, and
`rollback` goes back to it. To install an app for every account on the
computer, put `--system` first (`slate-flatpak --system install
org.gnome.Calculator`; likewise `remove`, `update` and `list`). That
asks for your password in Strata; in a terminal, run it as root.

Strata updates your Flatpak apps in the background every six hours or
so. The **Software Updater** shows when that last happened, can turn it
off and on, and has **Update apps** and **Roll back** for the app you
choose.

`slate-appimage FILE` runs an AppImage. It is unpacked once (FUSE isn't
needed) and runs on the freedesktop runtime, downloaded from Flathub the
first time. AppImages made for the terminal run in it.

- `slate-appimage --add FILE` puts it in Strata's launcher.
- `slate-appimage --list` shows the unpacked ones and their sizes.
- `slate-appimage --remove FILE` removes one, and `--clean` removes
  those whose file is gone.

## Network settings

SlateOS gets its address with DHCP unless you choose **Fixed address**
in the installer. To change it later, use **Settings › Network**, or
`slate-network` in a terminal (it asks for your password):

```sh
slate-network                # the settings, and each card's now
slate-network '*' static 192.168.1.20/24 \
    gateway 192.168.1.1 dns 9.9.9.9
slate-network eth1 dhcp      # one card back to DHCP
```

SlateOS uses the first network port that has a cable plugged in, and
moves to another port if you move the cable.

To use a fixed address just once, for example to reach the network
from the install stick: press `e` in the boot menu and add
`slate.ip=ADDRESS/PREFIX,GATEWAY,DNS` to the kernel command line, for
example `slate.ip=192.168.1.20/24,192.168.1.1,9.9.9.9`.

SlateOS's firewall lets in only SSH from other computers.
`slate-firewall allow tcp PORT` opens another port, and
`slate-firewall deny tcp PORT` closes it again; Settings › Security
shows the same.

## Installing without questions

For installing on many PCs, or on one you reach over a serial line,
the text installer can run unattended. Start **Install Slate (text
mode)**, type `shell` at the disk question, and run `slate-install`
with the disk's name and a file that holds the password:

```sh
slate-install --list          # the disks
slate-install --map sda       # what a disk holds
echo 'your-password' > /tmp/pw
slate-install --disk sda --password-file /tmp/pw --yes
```

An unattended install sets up a command-line system without disk
encryption, with that password for root instead of a personal account.
These options add to it:

| Option | What it does |
|---|---|
| `--network WORDS` | the network settings, in the same words `slate-network` takes (example below) |
| `--authorized-keys FILE` | SSH keys that may log in as root |
| `--linux-compat` | turn on Linux compatibility |
| `--full-graphics` | full graphics on supported AMD Radeon graphics |
| `--keyboard LAYOUT`, `--timezone ZONE` | the keyboard layout and the time zone |
| `--beside` | install in the disk's largest free space, keeping the rest |
| `--delete N` | with `--beside`: delete partition N first |
| `--root-size G` | with `--beside`: give SlateOS G GiB |
| `--overwrite-medium` | install onto the disk the installer started from |

For example, with a fixed address:

```sh
slate-install --disk sda --password-file /tmp/pw --yes \
    --network "* static 192.168.1.20/24 gateway 192.168.1.1"
```

The installer runs from memory, so `--overwrite-medium` can install
onto the very disk it started from: useful on a PC with a single disk,
when you wrote the install image to that disk instead of a stick.

## If something goes wrong

- **The stick doesn't start.** Check that Secure Boot is off, and try
  the stick's other entry in the firmware's boot menu (with or without
  "UEFI:").
- **"No disk to install on was found".** Check that the firmware's SATA
  mode is AHCI, and that the disk has 2 GB or more. Type `shell` and run
  `dmesg` to see what the system found.
- **The keyboard does nothing.** Plug it straight into the PC rather
  than into a separate USB hub. You can plug it in after the installer
  has started; it is picked up within a second.
- **The network address shows "none yet".** Check the cable, and that
  the PC's network port is one SlateOS supports (see "What SlateOS runs
  on"). A USB Ethernet adapter is the easy way around an unsupported
  port.
- **The graphical installer looks wrong or doesn't react.** Restart and
  choose **Install Slate (text mode)** in the boot menu.
- **The screen stays dark after choosing full graphics.** Wait: after
  20 seconds SlateOS goes back to its standard graphics by itself. Or
  restart and choose **Slate (standard graphics)** in the boot menu.
- **Anything else.** In the text installer, type `shell` for a command
  line, where `dmesg` shows the system's log. On an installed system,
  `/var/log/install.log` has the installation's log and `dmesg` the
  system's. A photo of the screen helps when you report a problem.

Some commands worth knowing on an installed system:

| Command | What it does |
|---|---|
| `dmesg` | the system's log |
| `cat /var/log/install.log` | the installation's log |
| `free`, `df`, `ps` | memory, disks, processes |
| `poweroff`, `reboot` | shut down or restart |
| `slate-compat status` | whether Linux programs may run (`on` and `off` change it) |

## Trying SlateOS in a virtual machine

### In GNOME Boxes

Create a new machine in Boxes from `slate.iso` and start it. Boxes's
settings for systems it doesn't know (legacy BIOS, an IDE disk and an
RTL8139 network card) work, but they are slow. For a faster machine,
shut it down and switch it to UEFI, with a virtio disk and network
card. Find its name, and open its settings in an editor:

```sh
virsh --connect qemu:///session list --all
virsh --connect qemu:///session edit boxes-unknown
```

Then, in the settings:

- change `<os>` to `<os firmware='efi'>`, and add inside it
  `<firmware><feature enabled='no' name='secure-boot'/></firmware>`;
- in the disk, change `<target .../>` to `<target dev='vda'
  bus='virtio'/>` and delete the disk's `<address .../>` line;
- in the network `<interface>`, change `<model type='rtl8139'/>` to
  `<model type='virtio'/>` and delete its `<address .../>` line.

Save, and start the machine in Boxes as usual. Give it 4 GiB of memory
or more if you'll try Firefox.

### In other virtual machines

SlateOS runs in QEMU and in tools built on it, such as virt-manager.
Choose a q35 machine with UEFI firmware and Secure Boot
off, a virtio disk, a virtio network card and virtio graphics, and
start it from `slate.iso`.

### From a source checkout

Without a USB stick, a checkout of the repository can run the installer
in a QEMU window on a virtual disk:

```sh
cargo xtask try-install         # the installer, on an empty disk
cargo xtask try-install --disk  # then: the installed system
```

The installer runs in the window (keyboard and mouse; the pointer
needs no grab), and the serial console is in the terminal (Ctrl-A X
quits QEMU). When the installer restarts, QEMU exits; the second
command starts the installed disk, asks for the disk's password, and
gives a login prompt in the window and the terminal. `ssh -p 2222
USERNAME@localhost` works too. The disk (`target/try-install-disk.img`)
is kept between runs; `--new-disk` starts again with an empty one.
