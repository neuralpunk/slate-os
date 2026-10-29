// SPDX-License-Identifier: MIT OR Apache-2.0

//! In-kernel test runner.
//!
//! Booting with `test` on the command line runs every registered test and
//! reports on the serial console with lines the host harness
//! (`cargo xtask test`) parses:
//!
//! ```text
//! SLATE-TEST: PASS <name>
//! SLATE-TEST: FAIL <name>
//! SLATE-TEST: DONE <passed>/<total>
//! ```
//!
//! The kernel then leaves QEMU through the `isa-debug-exit` device.
//!
//! `ktest.only=<prefix>,...` runs only the tests whose names start with
//! one of the prefixes. `ktest.crash=<name>` instead runs one deliberate crash (after printing
//! `SLATE-TEST: CRASH <name>`), so the harness can check that fatal faults
//! are reported correctly.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::qemu::{self, ExitCode};
use crate::kprintln;

static ACTIVE: AtomicBool = AtomicBool::new(false);

/// A test returns `Err` with a reason, or panics, to fail.
pub struct Test {
    pub name: &'static str,
    pub run: fn() -> Result<(), &'static str>,
}

/// Fail with `why` unless `cond` holds.
pub fn ensure(cond: bool, why: &'static str) -> Result<(), &'static str> {
    if cond { Ok(()) } else { Err(why) }
}

/// A small deterministic xorshift generator for randomized tests.
#[derive(Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// All in-kernel test suites, in the order they run.
const SUITES: &[&[Test]] = &[
    &[Test { name: "boot", run: || Ok(()) }],
    crate::arch::tests::TESTS,
    crate::mm::tests::TESTS,
    crate::sched::tests::TESTS,
    crate::proc::tests::TESTS,
    crate::proc::apps::TESTS,
    crate::proc::profile::TESTS,
    crate::block::crypt::TESTS,
    crate::drivers::aml::TESTS,
    crate::drivers::acpi_events::TESTS,
    crate::drivers::nvme::TESTS,
    crate::drivers::input::hid::TESTS,
    crate::drivers::input::user::TESTS,
    crate::drivers::ahci::TESTS,
    crate::drivers::TESTS,
    crate::block::cache::TESTS,
    crate::block::elevator::TESTS,
    crate::fs::efivarfs::TESTS,
    crate::fs::tmpfs::TESTS,
    crate::fs::vfs::dcache::TESTS,
];

/// Mark the kernel as running in test mode (so a panic exits QEMU with a
/// failure instead of halting), if the command line asks for it.
pub fn activate_if_requested(cmdline: &str) {
    if cmdline.split_ascii_whitespace().any(|w| w == "test") {
        ACTIVE.store(true, Ordering::Relaxed);
    }
}

/// Whether the kernel booted in test mode.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Run every test (or the crash named by `ktest.crash=`), report, and exit QEMU.
pub fn run_all(cmdline: &str) -> ! {
    ACTIVE.store(true, Ordering::Relaxed);
    if let Some(name) = cmdline.split_ascii_whitespace().find_map(|w| w.strip_prefix("ktest.crash=")) {
        match crate::arch::tests::CRASHES.iter().find(|(n, _)| *n == name) {
            Some((_, crash)) => {
                kprintln!("SLATE-TEST: CRASH {name}");
                crash();
            }
            None => {
                kprintln!("SLATE-TEST: FAIL unknown crash {name:?}");
                qemu::exit(ExitCode::Failure);
            }
        }
    }
    // `ktest.only=A,B`: only the tests whose names start with A or B (for
    // chasing one failure).
    let only: alloc::vec::Vec<&str> = cmdline
        .split_ascii_whitespace()
        .find_map(|w| w.strip_prefix("ktest.only="))
        .map(|v| v.split(',').collect())
        .unwrap_or_default();
    let (mut passed, mut total) = (0, 0);
    for t in SUITES.iter().flat_map(|s| s.iter()) {
        if !only.is_empty() && !only.iter().any(|o| t.name.starts_with(o)) {
            continue;
        }
        total += 1;
        match (t.run)() {
            Ok(()) => {
                passed += 1;
                kprintln!("SLATE-TEST: PASS {}", t.name);
            }
            Err(why) => kprintln!("SLATE-TEST: FAIL {} ({why})", t.name),
        }
    }
    kprintln!("SLATE-TEST: DONE {passed}/{total}");
    // Close file systems as a clean shutdown would (the host checks the
    // disks afterwards).
    crate::fs::shutdown();
    qemu::exit(if passed == total { ExitCode::Success } else { ExitCode::Failure });
}
