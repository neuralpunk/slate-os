// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encrypted partitions (ADR 0036): a partition in `slatecrypt`'s format,
//! unlocked with a password, becomes a mapped device (`dm-0`) whose sectors
//! are decrypted as they are read and encrypted as they are written.
//!
//! The root is unlocked at boot, before init starts. With the `unlock`
//! module (ADR 0038), the boot's unlock program asks for the password and
//! derives the slot's key in user space; it hands the key over with the
//! native call `unlock`, and the kernel opens the slot with it (the key
//! wrap's check tells a wrong one).
//!
//! After boot, root in the Slate domain opens other encrypted partitions
//! the same way, with the native call `crypt_open` (ADR 0039): Argon2id
//! runs in user space (`slate-crypt`), the kernel checks the slot's key.
//! `/sys/block/dm-N/slaves/` names the partition under each device.
//!
//! Sectors use AES-NI where the CPU has it, in kernel FPU sections of at
//! most 64 KiB each (`arch::fpu::with_vectors`, ADR 0039).
//!
//! Without the module the kernel asks on the console itself, and Argon2id
//! runs in scratch memory. The argon2 crate picks AVX2 by itself where the
//! CPU has it, and the kernel saves vector registers only for user
//! threads; so the derivation runs with interrupts masked (no preemption,
//! no migration to another CPU), before any user thread exists. It takes
//! well under a second.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;

use slatecrypt::{Error, HEADER_BYTES, Header, Xts};

use super::{BlockDevice, IoError, SECTOR};
use crate::abi::linux::errno::{EACCES, EAGAIN, EBUSY, EINVAL, EIO, ENXIO, EPERM, Errno};
use crate::sync::IrqSpinLock;
use crate::{log_error, log_info};

/// An unlocked encrypted partition.
pub struct CryptDevice {
    name: String,
    inner: Arc<dyn BlockDevice>,
    /// Where the data starts on `inner`, in sectors.
    offset: u64,
    sectors: u64,
    xts: Xts,
}

impl BlockDevice for CryptDevice {
    fn name(&self) -> &str {
        &self.name
    }
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read_only(&self) -> bool {
        self.inner.read_only()
    }
    fn read(&self, sector: u64, buf: &mut [u8]) -> core::result::Result<(), IoError> {
        if sector + (buf.len() / SECTOR) as u64 > self.sectors {
            return Err(IoError);
        }
        self.inner.read(self.offset + sector, buf)?;
        crypt(&self.xts, sector, buf, false);
        Ok(())
    }
    fn write(&self, sector: u64, buf: &[u8]) -> core::result::Result<(), IoError> {
        if sector + (buf.len() / SECTOR) as u64 > self.sectors {
            return Err(IoError);
        }
        let mut sealed = buf.to_vec();
        crypt(&self.xts, sector, &mut sealed, true);
        self.inner.write(self.offset + sector, &sealed)
    }
    fn flush(&self) -> core::result::Result<(), IoError> {
        self.inner.flush()
    }
    fn removable(&self) -> bool {
        self.inner.removable()
    }
    /// Discards pass through to the partition (ADR 0039). Like every disk
    /// encryption that allows them, this shows which sectors are free.
    fn can_discard(&self) -> bool {
        self.inner.can_discard()
    }
    fn discard(&self, sector: u64, count: u64) -> core::result::Result<(), IoError> {
        if sector.checked_add(count).is_none_or(|end| end > self.sectors) {
            return Err(IoError);
        }
        self.inner.discard(self.offset + sector, count)
    }
}

/// How much one FPU section encrypts at most (interrupts wait for it).
const SECTION_BYTES: usize = 64 * 1024;

/// Encrypt or decrypt `buf` (whole sectors from `first`): with AES-NI in
/// FPU sections, else in software.
fn crypt(xts: &Xts, first: u64, buf: &mut [u8], encrypt: bool) {
    let run = |x: &Xts, s: u64, b: &mut [u8]| if encrypt { x.encrypt(s, b) } else { x.decrypt(s, b) };
    if !xts.accelerated() {
        return run(xts, first, buf);
    }
    for (i, chunk) in buf.chunks_mut(SECTION_BYTES).enumerate() {
        let s = first + (i * SECTION_BYTES / SECTOR) as u64;
        crate::arch::fpu::with_vectors(|| run(xts, s, chunk));
    }
}

/// Whether sectors use AES-NI, for the log.
pub fn aesni() -> bool {
    slatecrypt::aesni::available()
}

/// An open encrypted partition: its number N (`dm-N`), the partition, the
/// mapped device.
struct Mapped {
    rdev: u64,
    under: Arc<dyn BlockDevice>,
    dev: Arc<dyn BlockDevice>,
    /// The master key, for new key slots (`crypt_wrap`, ADR 0058); it
    /// never leaves the kernel.
    key: MasterKey,
}

/// A master key, wiped when it goes.
pub struct MasterKey([u8; slatecrypt::KEY_BYTES]);

impl Drop for MasterKey {
    fn drop(&mut self) {
        slatecrypt::wipe(&mut self.0);
    }
}

static MAPPED: IrqSpinLock<alloc::vec::Vec<Mapped>> = IrqSpinLock::new(alloc::vec::Vec::new());

/// Register the unlocked `dev` of partition `under`: its device number.
fn register(under: &Arc<dyn BlockDevice>, dev: Arc<dyn BlockDevice>, key: &[u8; slatecrypt::KEY_BYTES]) -> u64 {
    // Its I/O is counted for /proc/diskstats (ADR 0112).
    let counted = super::stats::Counted::mapped(dev);
    let stats = counted.stats.clone();
    let dev: Arc<dyn BlockDevice> = Arc::new(counted);
    // Known before sysfs adds the device's entries (which name it).
    MAPPED.lock().push(Mapped { rdev: 0, under: under.clone(), dev: dev.clone(), key: MasterKey(*key) });
    let rdev = super::register_mapped(dev.clone(), stats);
    if let Some(m) = MAPPED.lock().iter_mut().find(|m| Arc::ptr_eq(&m.dev, &dev)) {
        m.rdev = rdev;
    }
    rdev
}

/// The partition under mapped device `name` (`dm-N`), for sysfs.
pub fn slave_of(name: &str) -> Option<String> {
    MAPPED.lock().iter().find(|m| m.dev.name() == name).map(|m| String::from(m.under.name()))
}

/// The native call `crypt_open`: open `under` with the key for `slot`;
/// N of its `dm-N`.
pub fn open_with_key(under: &Arc<dyn BlockDevice>, slot: usize, kek: &[u8; 32]) -> Result<u32, Errno> {
    if MAPPED.lock().iter().any(|m| Arc::ptr_eq(&m.under, under)) {
        return Err(EBUSY);
    }
    let h = header(under).ok_or(EINVAL)?;
    let slot = h.slots.get(slot).copied().flatten().ok_or(EINVAL)?;
    let key = MasterKey(slatecrypt::unwrap_slot(&slot, kek).map_err(|_| EACCES)?);
    let d = with_key(under, &h, &key.0).map_err(|_| EINVAL)?;
    let rdev = register(under, d.clone(), &key.0);
    log_info!("crypt: /dev/{} unlocked as /dev/{}", under.name(), d.name());
    Ok(crate::fs::vfs::minor(rdev))
}

/// The native call `crypt_wrap`: `dm-N`'s master key wrapped under `kek`
/// (ADR 0058).
pub fn wrap_key(n: u32, kek: &[u8; 32]) -> Result<[u8; slatecrypt::WRAPPED_BYTES], Errno> {
    let rdev = crate::fs::vfs::makedev(super::MAPPED_MAJOR, n);
    let mapped = MAPPED.lock();
    let m = mapped.iter().find(|m| m.rdev == rdev).ok_or(ENXIO)?;
    slatecrypt::wrap(&m.key.0, kek).map_err(|_| EINVAL)
}

/// The native call `crypt_close`: close `dm-N` unless it is in use.
pub fn close(n: u32) -> Result<(), Errno> {
    let rdev = crate::fs::vfs::makedev(super::MAPPED_MAJOR, n);
    let mut mapped = MAPPED.lock();
    let i = mapped.iter().position(|m| m.rdev == rdev).ok_or(ENXIO)?;
    // In use: anything but this list and the registry holds the device.
    super::unregister_mapped(rdev, 1)?;
    let m = mapped.remove(i);
    log_info!("crypt: /dev/{} closed", m.dev.name());
    Ok(())
}

/// The encryption header at the start of `dev`, or its copy when the
/// first is damaged (ADR 0039), if it has one.
pub fn header(dev: &Arc<dyn BlockDevice>) -> Option<Header> {
    let mut b = vec![0u8; HEADER_BYTES];
    if dev.sectors() <= slatecrypt::DATA_OFFSET || dev.read(0, &mut b).is_err() {
        return None;
    }
    let mut copy = vec![0u8; HEADER_BYTES];
    let _ = dev.read(slatecrypt::BACKUP_OFFSET, &mut copy);
    match Header::parse_either(&b, &copy) {
        Ok(h) => Some(h),
        Err(Error::Damaged) => {
            log_error!("crypt: /dev/{}: both copies of the encryption header are damaged", dev.name());
            None
        }
        Err(_) => None,
    }
}

/// The unlocked device for `dev` with its master key, not yet registered.
fn with_key(
    dev: &Arc<dyn BlockDevice>,
    h: &Header,
    key: &[u8; slatecrypt::KEY_BYTES],
) -> Result<Arc<dyn BlockDevice>, Error> {
    let xts = Xts::new(key);
    let end = h.data_offset.checked_add(h.data_sectors).ok_or(Error::Unsupported)?;
    if end > dev.sectors() {
        return Err(Error::Unsupported);
    }
    Ok(Arc::new(CryptDevice {
        name: super::next_mapped_name(),
        inner: dev.clone(),
        offset: h.data_offset,
        sectors: h.data_sectors,
        xts,
    }))
}

/// The boot's unlock stage (ADR 0038): the root being unlocked, the
/// unlock program's pid (0 until it has started), and the device once its
/// key has come.
struct Stage {
    dev: Arc<dyn BlockDevice>,
    header: Header,
    what: String,
    pid: u32,
    unlocked: Option<(Arc<dyn BlockDevice>, u64)>,
}

static STAGE: IrqSpinLock<Option<Stage>> = IrqSpinLock::new(None);

/// The unlock stage begins: `dev` (named `what`) waits for its key.
pub fn begin_stage(dev: &Arc<dyn BlockDevice>, h: &Header, what: &str) {
    *STAGE.lock() = Some(Stage { dev: dev.clone(), header: *h, what: String::from(what), pid: 0, unlocked: None });
}

/// The unlock program has started as `pid`.
pub fn stage_program(pid: u32) {
    if let Some(s) = STAGE.lock().as_mut() {
        s.pid = pid;
    }
}

/// The stage ends: the unlocked device and its number, if the key came.
pub fn end_stage() -> Option<(Arc<dyn BlockDevice>, u64)> {
    STAGE.lock().take().and_then(|s| s.unlocked)
}

/// The native call `unlock`: the unlock program `pid` hands over the key
/// for key slot `slot`. EACCES if it does not open the slot (a wrong
/// password); EPERM from anyone else, or after the key came.
pub fn hand_over(pid: u32, slot: usize, kek: &[u8; 32]) -> Result<(), Errno> {
    let (dev, h, what) = {
        let g = STAGE.lock();
        let s = g.as_ref().ok_or(EPERM)?;
        if s.pid == 0 {
            return Err(EAGAIN);
        }
        if s.pid != pid || s.unlocked.is_some() {
            return Err(EPERM);
        }
        (s.dev.clone(), s.header, s.what.clone())
    };
    let slot = h.slots.get(slot).copied().flatten().ok_or(EINVAL)?;
    let key = MasterKey(slatecrypt::unwrap_slot(&slot, kek).map_err(|_| EACCES)?);
    let d = with_key(&dev, &h, &key.0).map_err(|e| {
        log_error!("crypt: cannot open {what}: {e:?}");
        EIO
    })?;
    let rdev = register(&dev, d.clone(), &key.0);
    log_info!("crypt: {what} unlocked as /dev/{}", d.name());
    if let Some(s) = STAGE.lock().as_mut() {
        s.unlocked = Some((d, rdev));
    }
    Ok(())
}

pub const TESTS: &[crate::ktest::Test] = &[
    crate::ktest::Test { name: "block::crypt_device", run: crypt_device },
    crate::ktest::Test { name: "block::crypt_aesni", run: crypt_aesni },
];

/// AES-NI in a kernel FPU section gives software AES's sectors, and leaves
/// the vector registers as they were (ADR 0039).
fn crypt_aesni() -> Result<(), &'static str> {
    use crate::ktest::ensure;
    if !aesni() {
        crate::log_info!("crypt: no AES-NI on this CPU; software AES only");
        return Ok(());
    }
    let key: [u8; slatecrypt::KEY_BYTES] = core::array::from_fn(|i| (i * 7 + 1) as u8);
    let (ni, soft) = (Xts::with_aesni(&key, true), Xts::with_aesni(&key, false));
    ensure(ni.accelerated() && !soft.accelerated(), "AES-NI not chosen")?;
    let plain: alloc::vec::Vec<u8> = (0..4 * SECTOR).map(|i| (i % 253) as u8).collect();
    let (mut a, mut b) = (plain.clone(), plain.clone());
    soft.encrypt(77, &mut a);
    crypt(&ni, 77, &mut b, true);
    ensure(a == b, "AES-NI and software sectors differ")?;
    crypt(&ni, 77, &mut b, false);
    ensure(b == plain, "AES-NI did not decrypt")?;
    // Speed, for the log: 4 MiB each way.
    let mut big = vec![0u8; 4 << 20];
    let t0 = crate::time::monotonic_ns();
    crypt(&ni, 0, &mut big, true);
    let t1 = crate::time::monotonic_ns();
    soft.encrypt(0, &mut big[..1 << 20]);
    let t2 = crate::time::monotonic_ns();
    let mbs = |bytes: u64, ns: u64| bytes * 1000 / ns.max(1);
    crate::log_info!("crypt: AES-NI {} MB/s, software {} MB/s", mbs(4 << 20, t1 - t0), mbs(1 << 20, t2 - t1));
    Ok(())
}

/// A disk in memory, for the test.
struct RamDisk(crate::sync::IrqSpinLock<alloc::vec::Vec<u8>>);

impl BlockDevice for RamDisk {
    fn name(&self) -> &str {
        "ram"
    }
    fn sectors(&self) -> u64 {
        (self.0.lock().len() / SECTOR) as u64
    }
    fn read_only(&self) -> bool {
        false
    }
    fn read(&self, sector: u64, buf: &mut [u8]) -> core::result::Result<(), IoError> {
        let d = self.0.lock();
        let at = sector as usize * SECTOR;
        buf.copy_from_slice(d.get(at..at + buf.len()).ok_or(IoError)?);
        Ok(())
    }
    fn write(&self, sector: u64, buf: &[u8]) -> core::result::Result<(), IoError> {
        let mut d = self.0.lock();
        let at = sector as usize * SECTOR;
        d.get_mut(at..at + buf.len()).ok_or(IoError)?.copy_from_slice(buf);
        Ok(())
    }
    fn flush(&self) -> core::result::Result<(), IoError> {
        Ok(())
    }
}

/// A header made as the installer makes it opens with its password (and
/// only with it); data written through the device is ciphertext on the
/// disk and reads back.
fn crypt_device() -> Result<(), &'static str> {
    use crate::ktest::ensure;
    let sectors = slatecrypt::DATA_OFFSET + 64;
    let ram: Arc<dyn BlockDevice> =
        Arc::new(RamDisk(crate::sync::IrqSpinLock::new(vec![0; sectors as usize * SECTOR])));
    // A slot wrapped from a key-encryption key, as the unlock program
    // hands one over (the kernel derives none from passwords, ADR 0086).
    let quick = slatecrypt::Params { memory_kib: 256, passes: 1, lanes: 1 };
    let key = [0x5a; slatecrypt::KEY_BYTES];
    let kek = [5u8; 32];
    let wrapped = slatecrypt::wrap(&key, &kek).map_err(|_| "wrap")?;
    let mut h = Header::new(sectors, [3; 16]);
    h.slots[0] = Some(slatecrypt::Slot {
        kind: slatecrypt::SlotKind::Password,
        params: quick,
        salt: [4; 32],
        wrapped,
        owner: None,
    });
    ram.write(0, &h.to_bytes()).map_err(|_| "writing the header")?;
    ram.write(slatecrypt::BACKUP_OFFSET, &h.to_bytes()).map_err(|_| "writing the header's copy")?;
    // The first copy damaged: the second is read (ADR 0039).
    ram.write(0, &[0xEE; SECTOR]).map_err(|_| "damaging the header")?;
    let found = header(&ram).ok_or("no header found")?;
    let slot = found.slots[0].ok_or("slot")?;
    ensure(slatecrypt::unwrap_slot(&slot, &[6u8; 32]).is_err(), "a wrong key opened it")?;
    let unwrapped = slatecrypt::unwrap_slot(&slot, &kek).map_err(|_| "the key did not open it")?;
    ensure(unwrapped == key, "the wrapped key did not unwrap")?;
    let dev = with_key(&ram, &found, &unwrapped).map_err(|_| "opening with the key")?;
    ensure(dev.sectors() == 64, "data size")?;
    let data: alloc::vec::Vec<u8> = (0..1024).map(|i| (i % 7) as u8).collect();
    dev.write(10, &data).map_err(|_| "write")?;
    let mut back = vec![0u8; 1024];
    dev.read(10, &mut back).map_err(|_| "read")?;
    ensure(back == data, "data did not read back")?;
    let mut raw = vec![0u8; 1024];
    ram.read(slatecrypt::DATA_OFFSET + 10, &mut raw).map_err(|_| "raw read")?;
    ensure(raw != data, "data is plain on the disk")?;
    ensure(dev.read(63, &mut back).is_err(), "read past the end")
}
