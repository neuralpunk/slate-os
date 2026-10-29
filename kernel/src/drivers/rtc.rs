// SPDX-License-Identifier: MIT OR Apache-2.0

//! The CMOS real-time clock (MC146818-compatible) through I/O ports 0x70
//! (index) and 0x71 (data); the formats are slate-rtc's. The clock holds
//! UTC. It gives the wall-clock time at boot, and setting the system time
//! writes it back (M19, ADR 0044).

use core::sync::atomic::{AtomicBool, Ordering};

use slate_rtc::{Cmos, DateTime};

use crate::arch::port::Port8;
use crate::sync::IrqSpinLock;

/// Index and data ports; index bit 7 masks NMIs, so it stays clear.
struct Ports {
    index: Port8,
    data: Port8,
}

impl Cmos for Ports {
    fn read(&mut self, reg: u8) -> u8 {
        self.index.write(reg & 0x7F);
        self.data.read()
    }
    fn write(&mut self, reg: u8, value: u8) {
        self.index.write(reg & 0x7F);
        self.data.write(value);
    }
}

/// The ports: index and data must go together.
static PORTS: IrqSpinLock<Ports> = IrqSpinLock::new(Ports {
    // SAFETY: 0x70/0x71 are the CMOS index and data ports: they reach the
    // RTC's and the CMOS's registers only, never memory.
    index: unsafe { Port8::new(0x70) },
    // SAFETY: As above.
    data: unsafe { Port8::new(0x71) },
});

/// The clock was written since boot (the system time was set).
static WRITTEN: AtomicBool = AtomicBool::new(false);

/// Whether the machine has a CMOS RTC (the FADT can say it has none), and
/// its century register.
fn present() -> Option<Option<u8>> {
    let fadt = crate::acpi::info().fadt;
    if fadt.is_some_and(|f| f.iapc_boot_arch & slate_acpi::fadt::BOOT_ARCH_NO_CMOS_RTC != 0) {
        return None;
    }
    // CENTURY: the CMOS register holding the century, 0 for none (ACPI
    // 6.5 §5.2.9, table 5.9).
    Some(fadt.map(|f| f.century).filter(|&c| c != 0 && c < 0x80))
}

/// The clock's time, as Unix seconds.
pub fn read_unix() -> Option<i64> {
    let century = present()?;
    slate_rtc::read(&mut *PORTS.lock(), century).map(|t| t.to_unix())
}

/// The clock's time, broken down (for /proc/driver/rtc).
pub fn read() -> Option<DateTime> {
    let century = present()?;
    slate_rtc::read(&mut *PORTS.lock(), century)
}

/// Set the clock to Unix time `secs`.
pub fn write_unix(secs: i64) -> bool {
    let Some(century) = present() else { return false };
    let ok = slate_rtc::write(&mut *PORTS.lock(), century, &DateTime::from_unix(secs));
    if ok {
        WRITTEN.store(true, Ordering::Release);
    }
    ok
}

/// The system time to the clock, at the next whole second (from a kernel
/// timer), so the clock, which only holds seconds, is off by as little as
/// the tick allows.
pub fn sync_from_system() {
    if present().is_none() {
        return;
    }
    let into = crate::time::realtime_ns().rem_euclid(1_000_000_000) as u64;
    crate::time::add_timer(crate::time::monotonic_ns() + (1_000_000_000 - into), || {
        let ns = crate::time::realtime_ns();
        write_unix(((ns + 500_000_000).div_euclid(1_000_000_000)) as i64);
    });
}

/// At power-off: if the system time was set during this boot, the clock
/// gets it once more (keeping what passed since).
pub fn sync_at_shutdown() {
    if WRITTEN.load(Ordering::Acquire) {
        write_unix((crate::time::realtime_ns() / 1_000_000_000) as i64);
    }
}
