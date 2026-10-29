// SPDX-License-Identifier: MIT OR Apache-2.0

//! The other CPUs (ADR 0089). The ACPI MADT lists them (ACPI 6.5
//! §5.2.12). Each is woken with INIT and two start-up IPIs (Intel SDM
//! vol. 3A §9.4.4) into a trampoline below 1 MiB. The trampoline goes from
//! real mode to long mode on the tables that map the loader one to one,
//! moves to its direct-map alias and the kernel's own tables, and waits
//! for the kernel to write a `goto_address` (the protocol's MP feature).
//! It carries the GDT the protocol describes, which the bootstrap CPU
//! loads too:
//!
//! ```text
//! 0x00 null   0x08 16-bit code  0x10 16-bit data  0x18 32-bit code
//! 0x20 32-bit data  0x28 64-bit code  0x30 64-bit data
//! ```

use alloc::vec::Vec;
use core::mem::offset_of;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::cpu;
use crate::proto::{HHDM, MP_GOTO, MpInfo};

/// A CPU the firmware describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cpu {
    pub uid: u32,
    pub apic_id: u32,
}

/// The enabled CPUs of a MADT, without repeats (a CPU can be listed as a
/// local APIC and as a local x2APIC).
pub fn cpus(madt: &[u8]) -> Vec<Cpu> {
    use slate_acpi::madt::{Entry, LAPIC_ENABLED};
    let Some(m) = slate_acpi::madt::parse(madt) else { return Vec::new() };
    let mut out: Vec<Cpu> = Vec::new();
    for e in m.entries() {
        let cpu = match e {
            Entry::LocalApic { processor_uid, apic_id, flags } if flags & LAPIC_ENABLED != 0 => {
                Cpu { uid: u32::from(processor_uid), apic_id: u32::from(apic_id) }
            }
            Entry::LocalX2Apic { x2apic_id, flags, processor_uid } if flags & LAPIC_ENABLED != 0 => {
                Cpu { uid: processor_uid, apic_id: x2apic_id }
            }
            _ => continue,
        };
        if !out.iter().any(|c| c.apic_id == cpu.apic_id) {
            out.push(cpu);
        }
    }
    out
}

/// The protocol's GDT.
pub const GDT: [u64; 7] = [
    0,
    0x0000_9a00_0000_ffff,
    0x0000_9200_0000_ffff,
    0x00cf_9a00_0000_ffff,
    0x00cf_9200_0000_ffff,
    0x00af_9a00_0000_ffff,
    0x00cf_9200_0000_ffff,
];
pub const CODE64: u16 = 0x28;
const CODE32: u16 = 0x18;

/// The trampoline's data, after its code in the same page.
#[repr(C, align(16))]
#[derive(Debug)]
pub struct TrampolineData {
    pub gdt: [u64; 8],
    /// Limit and 32-bit base, as LGDT reads them in 16-bit code.
    gdtr32: [u16; 4],
    /// m16:32 far pointers: offset, then selector.
    pm_target: [u32; 2],
    lm_target: [u32; 2],
    cr3_identity: u64,
    hhdm: u64,
    cr3_kernel: u64,
    /// Limit and 64-bit base (the direct-map alias of `gdt`).
    pub gdtr64: [u16; 8],
    x2apic: u64,
    info: u64,
    stack: u64,
    started: AtomicU64,
}

core::arch::global_asm!(
    ".globl slate_ap_start",
    ".globl slate_ap_pm",
    ".globl slate_ap_data",
    ".globl slate_ap_end",
    ".balign 16",
    ".code16",
    "slate_ap_start:",
    "    cli",
    "    cld",
    "    mov %cs, %ax",
    "    mov %ax, %ds",
    // The page's linear address, for the 32-bit code.
    "    xor %ebx, %ebx",
    "    mov %cs, %bx",
    "    shl $4, %ebx",
    "    lgdtl (slate_ap_data - slate_ap_start + {gdtr32})",
    // Protection on, caching on (INIT leaves CD and NW set).
    "    mov %cr0, %eax",
    "    and $0x9fffffff, %eax",
    "    or $1, %eax",
    "    mov %eax, %cr0",
    "    ljmpl *(slate_ap_data - slate_ap_start + {pm_target})",
    ".code32",
    "slate_ap_pm:",
    "    mov $0x20, %ax",
    "    mov %ax, %ds",
    "    mov %ax, %es",
    "    mov %ax, %ss",
    // PAE, the one-to-one tables, long mode and no-execute, paging.
    "    mov %cr4, %eax",
    "    or $0x20, %eax",
    "    mov %eax, %cr4",
    "    mov (slate_ap_data - slate_ap_start + {cr3_identity})(%ebx), %eax",
    "    mov %eax, %cr3",
    "    mov $0xc0000080, %ecx",
    "    rdmsr",
    "    or $0x900, %eax",
    "    wrmsr",
    "    mov %cr0, %eax",
    "    or $0x80010000, %eax",
    "    mov %eax, %cr0",
    "    lea (slate_ap_lm - slate_ap_start)(%ebx), %eax",
    "    mov %eax, (slate_ap_data - slate_ap_start + {lm_target})(%ebx)",
    "    ljmp *(slate_ap_data - slate_ap_start + {lm_target})(%ebx)",
    ".code64",
    "slate_ap_lm:",
    // On to the page's direct-map alias, and the kernel's tables.
    "    mov %ebx, %ebx",
    "    add (slate_ap_data - slate_ap_start + {hhdm})(%rbx), %rbx",
    "    lea (2f - slate_ap_start)(%rbx), %rax",
    "    jmp *%rax",
    "2:",
    "    mov (slate_ap_data - slate_ap_start + {cr3_kernel})(%rbx), %rax",
    "    mov %rax, %cr3",
    "    lgdt (slate_ap_data - slate_ap_start + {gdtr64})(%rbx)",
    "    mov (slate_ap_data - slate_ap_start + {stack})(%rbx), %rsp",
    "    lea (3f - slate_ap_start)(%rbx), %rax",
    "    pushq ${code64}",
    "    push %rax",
    "    lretq",
    "3:",
    "    mov $0x30, %eax",
    "    mov %eax, %ds",
    "    mov %eax, %es",
    "    mov %eax, %ss",
    "    mov %eax, %fs",
    "    mov %eax, %gs",
    "    cmpq $0, (slate_ap_data - slate_ap_start + {x2apic})(%rbx)",
    "    je 4f",
    "    mov $0x1b, %ecx",
    "    rdmsr",
    "    or $0xc00, %eax",
    "    wrmsr",
    "4:",
    "    mov (slate_ap_data - slate_ap_start + {info})(%rbx), %rdi",
    // Done with the shared data: the next CPU may have it.
    "    movq $1, (slate_ap_data - slate_ap_start + {started})(%rbx)",
    "5:",
    "    pause",
    "    mov {goto}(%rdi), %rax",
    "    test %rax, %rax",
    "    jz 5b",
    "    xor %ebp, %ebp",
    "    pushq $0",
    "    jmp *%rax",
    ".balign 16",
    "slate_ap_data:",
    ".fill {data_len}, 1, 0",
    "slate_ap_end:",
    gdtr32 = const offset_of!(TrampolineData, gdtr32),
    pm_target = const offset_of!(TrampolineData, pm_target),
    lm_target = const offset_of!(TrampolineData, lm_target),
    cr3_identity = const offset_of!(TrampolineData, cr3_identity),
    hhdm = const offset_of!(TrampolineData, hhdm),
    cr3_kernel = const offset_of!(TrampolineData, cr3_kernel),
    gdtr64 = const offset_of!(TrampolineData, gdtr64),
    x2apic = const offset_of!(TrampolineData, x2apic),
    info = const offset_of!(TrampolineData, info),
    stack = const offset_of!(TrampolineData, stack),
    started = const offset_of!(TrampolineData, started),
    goto = const MP_GOTO,
    code64 = const CODE64,
    data_len = const core::mem::size_of::<TrampolineData>(),
    options(att_syntax),
);

unsafe extern "C" {
    static slate_ap_start: u8;
    static slate_ap_pm: u8;
    static slate_ap_data: u8;
    static slate_ap_end: u8;
}

fn symbols() -> (usize, usize, usize, usize) {
    (
        core::ptr::addr_of!(slate_ap_start) as usize,
        core::ptr::addr_of!(slate_ap_pm) as usize,
        core::ptr::addr_of!(slate_ap_data) as usize,
        core::ptr::addr_of!(slate_ap_end) as usize,
    )
}

/// The trampoline's size; it must fit one page.
pub fn trampoline_len() -> usize {
    let (start, _, _, end) = symbols();
    end - start
}

/// A trampoline copied to a page below 1 MiB.
#[derive(Debug)]
pub struct Trampoline {
    page: u64,
    data: *mut TrampolineData,
}

impl Trampoline {
    /// Copy the trampoline to `page` (physical, below 1 MiB, page-aligned,
    /// reachable one to one) and fill in its tables: `identity` (below 4
    /// GiB) for the switch to long mode, `kernel` for the wait.
    ///
    /// # Safety
    /// `page` must be a whole page of memory the loader owns, identity
    /// mapped now.
    pub unsafe fn install(page: u64, identity: u64, kernel: u64, x2apic: bool) -> Trampoline {
        let (start, pm, data, end) = symbols();
        assert!(page < 0x10_0000 && page % 4096 == 0 && end - start <= 4096 && identity < 1 << 32);
        // SAFETY: The caller gives the page; the code is `end - start`
        // bytes of the loader's own text.
        unsafe { core::ptr::copy_nonoverlapping(start as *const u8, page as *mut u8, end - start) };
        let d = (page as usize + (data - start)) as *mut TrampolineData;
        // SAFETY: `d` is in the page just written, aligned like the label.
        let t = unsafe { &mut *d };
        t.gdt[..GDT.len()].copy_from_slice(&GDT);
        let limit = (GDT.len() * 8 - 1) as u16;
        let gdt = page + (data - start) as u64;
        t.gdtr32 = [limit, gdt as u16, (gdt >> 16) as u16, 0];
        t.pm_target = [(page + (pm - start) as u64) as u32, u32::from(CODE32)];
        t.lm_target = [0, u32::from(CODE64)];
        t.cr3_identity = identity;
        t.hhdm = HHDM;
        t.cr3_kernel = kernel;
        let g = HHDM + gdt;
        t.gdtr64 = [limit, g as u16, (g >> 16) as u16, (g >> 32) as u16, (g >> 48) as u16, 0, 0, 0];
        t.x2apic = u64::from(x2apic);
        Trampoline { page, data: d }
    }

    /// The GDT register's value for the kernel's tables (the bootstrap
    /// CPU loads it too).
    pub fn gdtr64(&self) -> [u16; 8] {
        // SAFETY: `data` stays the trampoline's while the loader runs.
        unsafe { (*self.data).gdtr64 }
    }

    /// Start the CPUs in `infos` but the bootstrap one: INIT to each, 10 ms,
    /// then one at a time a start-up IPI (a second after 200 µs if it has
    /// not answered) and a wait until it has taken its `stack`. Returns
    /// whether each started.
    ///
    /// # Safety
    /// After ExitBootServices (or on BIOS), with the APIC reachable: in
    /// x2APIC mode, or its registers mapped one to one.
    pub unsafe fn start(&self, infos: &[(u32, u64, u64)], bsp: u32, x2apic: bool, tsc_per_us: u64) -> Vec<bool> {
        let icr = |dest: u32, low: u32| {
            if x2apic {
                // SAFETY: The x2APIC's ICR (MSR 830h, vol. 3A §11.12.9).
                unsafe { cpu::wrmsr(0x830, u64::from(dest) << 32 | u64::from(low)) };
            } else {
                // SAFETY: The xAPIC's ICR, high then low (vol. 3A
                // §11.6.1), at the APIC base the MSR gives.
                unsafe {
                    let base = (cpu::rdmsr(cpu::APIC_BASE) & 0xf_ffff_f000) as usize;
                    core::ptr::write_volatile((base + 0x310) as *mut u32, dest << 24);
                    core::ptr::write_volatile((base + 0x300) as *mut u32, low);
                    while core::ptr::read_volatile((base + 0x300) as *const u32) & (1 << 12) != 0 {
                        core::hint::spin_loop();
                    }
                }
            }
        };
        // INIT, level assert (delivery mode 101b).
        for &(apic, _, _) in infos.iter().filter(|i| i.0 != bsp) {
            icr(apic, 0x4500);
        }
        cpu::delay(10_000, tsc_per_us);
        // SAFETY: `data` is the trampoline's, see `install`.
        let d = unsafe { &mut *self.data };
        let vector = (self.page >> 12) as u32;
        infos
            .iter()
            .map(|&(apic, info, stack)| {
                if apic == bsp {
                    return true;
                }
                d.info = info;
                d.stack = stack;
                d.started.store(0, Ordering::SeqCst);
                let answered = |us: u64| {
                    let end = cpu::rdtsc() + us * tsc_per_us;
                    while cpu::rdtsc() < end {
                        if d.started.load(Ordering::SeqCst) != 0 {
                            return true;
                        }
                        core::hint::spin_loop();
                    }
                    false
                };
                // Start-up (delivery mode 110b), the page as the vector.
                icr(apic, 0x4600 | vector);
                if answered(200) {
                    return true;
                }
                icr(apic, 0x4600 | vector);
                answered(100_000)
            })
            .collect()
    }
}

/// An MP response entry for each CPU: the info structure's direct-map
/// address in a block the caller placed.
pub fn info(cpu: &Cpu) -> MpInfo {
    MpInfo { processor_id: cpu.uid, lapic_id: cpu.apic_id, ..Default::default() }
}

/// Turn on x2APIC mode on this CPU.
///
/// # Safety
/// The processor must support it.
pub unsafe fn enable_x2apic() {
    // SAFETY: The caller checked CPUID; enabling the APIC and then x2APIC
    // in one write is allowed from either state (vol. 3A §11.12.5).
    unsafe {
        let v = cpu::rdmsr(cpu::APIC_BASE);
        cpu::wrmsr(cpu::APIC_BASE, v | cpu::APIC_ENABLE | cpu::APIC_X2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn madt_cpus() {
        // Header (36), local APIC address and flags (8), then entries.
        let mut t = alloc::vec![0u8; 44];
        t.extend_from_slice(&[0, 8, 0, 0, 1, 0, 0, 0]); // uid 0, APIC 0, enabled
        t.extend_from_slice(&[0, 8, 1, 2, 1, 0, 0, 0]); // uid 1, APIC 2
        t.extend_from_slice(&[0, 8, 2, 4, 0, 0, 0, 0]); // disabled
        // x2APIC 2 again, and x2APIC 300.
        t.extend_from_slice(&[9, 16, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]);
        t.extend_from_slice(&[9, 16, 0, 0, 44, 1, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0]);
        let got = cpus(&t);
        assert_eq!(got, [Cpu { uid: 0, apic_id: 0 }, Cpu { uid: 1, apic_id: 2 }, Cpu { uid: 9, apic_id: 300 }]);
    }

    #[test]
    fn trampoline_fits_a_page() {
        assert!(trampoline_len() <= 4096 - 64);
        assert_eq!(offset_of!(TrampolineData, gdtr32) % 8, 0);
    }
}
