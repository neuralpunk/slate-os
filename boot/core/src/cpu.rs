// SPDX-License-Identifier: MIT OR Apache-2.0

//! Processor instructions the loader needs (Intel SDM vol. 2).

use core::arch::asm;

/// CPUID: (eax, ebx, ecx, edx) for `leaf` and `sub`.
pub fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let (a, b, c, d): (u32, u32, u32, u32);
    // SAFETY: CPUID only reads processor information; rbx, which LLVM
    // reserves, is saved around it.
    unsafe {
        asm!(
            "mov {t:r}, rbx",
            "cpuid",
            "xchg {t:r}, rbx",
            t = out(reg) b,
            inout("eax") leaf => a,
            inout("ecx") sub => c,
            out("edx") d,
            options(nostack, preserves_flags),
        );
    }
    (a, b, c, d)
}

/// 1 GiB pages (CPUID 80000001h:EDX[26]).
pub fn gigabyte_pages() -> bool {
    cpuid(0x8000_0000, 0).0 >= 0x8000_0001 && cpuid(0x8000_0001, 0).3 & (1 << 26) != 0
}

/// x2APIC mode (CPUID 01h:ECX[21]).
pub fn has_x2apic() -> bool {
    cpuid(1, 0).2 & (1 << 21) != 0
}

/// This processor's APIC ID: the x2APIC ID (CPUID 0Bh:EDX) when the leaf
/// is there, else the 8-bit one (CPUID 01h:EBX[31:24]).
pub fn apic_id() -> u32 {
    if cpuid(0, 0).0 >= 0xb && cpuid(0xb, 0).1 != 0 { cpuid(0xb, 0).3 } else { cpuid(1, 0).1 >> 24 }
}

/// The time-stamp counter.
pub fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: RDTSC reads a counter and nothing else.
    unsafe { asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    u64::from(hi) << 32 | u64::from(lo)
}

/// A random number for the kernel's place (KASLR, ADR 0095): RDSEED, else
/// RDRAND (Intel SDM vol. 1 §7.3.17; CPUID.07H:EBX bit 18, CPUID.01H:ECX
/// bit 30), else the time-stamp counter mixed.
pub fn random_u64() -> u64 {
    let ok = |f: &dyn Fn() -> Option<u64>| (0..10).find_map(|_| f());
    let seed = || {
        let (v, c): (u64, u8);
        // SAFETY: RDSEED writes a register and the carry flag, nothing else
        // (checked to exist below).
        unsafe { asm!("rdseed {}", "setc {}", out(reg) v, out(reg_byte) c, options(nomem, nostack)) };
        (c != 0).then_some(v)
    };
    let rand = || {
        let (v, c): (u64, u8);
        // SAFETY: As for RDSEED.
        unsafe { asm!("rdrand {}", "setc {}", out(reg) v, out(reg_byte) c, options(nomem, nostack)) };
        (c != 0).then_some(v)
    };
    if cpuid(0, 0).0 >= 7
        && cpuid(7, 0).1 & (1 << 18) != 0
        && let Some(v) = ok(&seed)
    {
        return v;
    }
    if cpuid(1, 0).2 & (1 << 30) != 0
        && let Some(v) = ok(&rand)
    {
        return v;
    }
    // splitmix64's finalizer over the counter (Steele, Lea and Flood,
    // "Fast splittable pseudorandom number generators").
    let mut z = rdtsc().wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// # Safety
/// `msr` must exist on this processor.
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: The caller names an MSR that exists.
    unsafe { asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    u64::from(hi) << 32 | u64::from(lo)
}

/// # Safety
/// `msr` must exist, and the value must not break what runs next.
pub unsafe fn wrmsr(msr: u32, value: u64) {
    // SAFETY: The caller vouches for the MSR and the value.
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") value as u32, in("edx") (value >> 32) as u32, options(nostack, preserves_flags))
    };
}

pub fn cr4() -> u64 {
    let v: u64;
    // SAFETY: Reading CR4 has no effect.
    unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// IA32_EFER and its no-execute enable (SDM vol. 3A §2.2.1).
pub const EFER: u32 = 0xC000_0080;
pub const EFER_NXE: u64 = 1 << 11;
/// IA32_APIC_BASE: the APIC's enable and x2APIC bits (vol. 3A §11.4.4).
pub const APIC_BASE: u32 = 0x1B;
pub const APIC_ENABLE: u64 = 1 << 11;
pub const APIC_X2: u64 = 1 << 10;
/// CR4.LA57: 5-level paging, which these tables are not.
pub const CR4_LA57: u64 = 1 << 12;

/// Spin for `us` microseconds, at `tsc_per_us`.
pub fn delay(us: u64, tsc_per_us: u64) {
    let end = rdtsc() + us * tsc_per_us.max(1);
    while rdtsc() < end {
        core::hint::spin_loop();
    }
}
