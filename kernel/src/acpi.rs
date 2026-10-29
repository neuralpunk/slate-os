// SPDX-License-Identifier: MIT OR Apache-2.0

//! ACPI static tables: what the kernel learns from them at boot.
//!
//! Parsing lives in `slate-acpi`; this module finds the tables through the
//! direct map and keeps the results.

use alloc::vec::Vec;

use slate_acpi::{GenericAddress, fadt, madt};
use slate_sync::Once;

use crate::arch::paging;
use crate::mm::PhysAddr;
use crate::{log_info, log_warn};

/// A processor listed in the MADT.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // Parsed for completeness and debugging output.
pub struct Cpu {
    pub processor_uid: u32,
    pub apic_id: u32,
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // Parsed for completeness and debugging output.
pub struct IoApic {
    pub id: u8,
    pub address: u64,
    pub gsi_base: u32,
}

/// A table as it is in memory (§5.2.6: signature, OEM ID, OEM table ID).
#[derive(Clone, Copy, Debug)]
pub struct Table {
    pub signature: [u8; 4],
    pub oem: [u8; 6],
    pub oem_table: [u8; 8],
    pub phys: u64,
    pub bytes: &'static [u8],
}

impl Table {
    fn new(phys: u64, bytes: &'static [u8]) -> Table {
        Table {
            signature: bytes[0..4].try_into().unwrap(),
            oem: bytes[10..16].try_into().unwrap(),
            oem_table: bytes[16..24].try_into().unwrap(),
            phys,
            bytes,
        }
    }
}

/// An ISA interrupt that is not wired to the GSI of the same number.
#[derive(Clone, Copy, Debug)]
pub struct Override {
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

#[derive(Debug, Default)]
pub struct Info {
    pub local_apic_address: u64,
    pub has_8259: bool,
    pub cpus: Vec<Cpu>,
    pub io_apics: Vec<IoApic>,
    pub overrides: Vec<Override>,
    /// LINT pin wired to NMI, per the MADT (one entry applies to all CPUs).
    pub nmi_lint: Option<(u8, u16)>,
    pub hpet: Option<GenericAddress>,
    pub fadt: Option<fadt::Fadt>,
    /// PCI Express configuration space regions (MCFG).
    pub mcfg: Vec<slate_acpi::mcfg::Entry>,
    /// Every table the root table lists, and the DSDT (for AML, ADR 0079).
    pub tables: Vec<Table>,
    /// RAM as the firmware reported it (usable, ACPI and the kernel's),
    /// kept past the bootloader's data: AML reads it through the direct
    /// map and everything else uncached.
    pub ram: Vec<(u64, u64)>,
    /// `\_S5` sleep type values (SLP_TYPa, SLP_TYPb).
    pub s5: Option<(u8, u8)>,
}

static INFO: Once<Info> = Once::new();

/// The parsed tables. Panics before [`init`].
pub fn info() -> &'static Info {
    INFO.get().expect("ACPI not initialized")
}

/// A validated table at physical address `phys`.
fn table_at(phys: u64, sig: Option<&[u8; 4]>) -> Option<&'static [u8]> {
    paging::ensure_direct_mapped(phys, slate_acpi::HEADER_LEN as u64);
    let p = PhysAddr(phys).to_virt();
    // SAFETY: The header was just mapped in the direct map; firmware tables
    // are never written by the OS.
    let header = unsafe { core::slice::from_raw_parts(p, slate_acpi::HEADER_LEN) };
    let len = slate_acpi::parse_header(header).ok()?.length as usize;
    paging::ensure_direct_mapped(phys, len as u64);
    // SAFETY: As above, for the table's full length.
    let bytes = unsafe { core::slice::from_raw_parts(p, len) };
    match slate_acpi::validate(bytes, sig) {
        Ok(t) => Some(t),
        Err(e) => {
            log_warn!("ignoring ACPI table at {phys:#x}: {e:?}");
            None
        }
    }
}

/// Read the RSDP at `rsdp_virt` and everything the kernel needs from the
/// tables it points to.
pub fn init(rsdp_virt: u64) {
    INFO.call_once(|| {
        paging::ensure_direct_mapped(rsdp_virt - crate::mm::hhdm_offset(), slate_acpi::RSDP_MAX_LEN as u64);
        // SAFETY: The bootloader reports the RSDP's direct-map address, and
        // its (at most 36) bytes were just mapped.
        let raw = unsafe { core::slice::from_raw_parts(rsdp_virt as *const u8, slate_acpi::RSDP_MAX_LEN) };
        let rsdp = slate_acpi::parse_rsdp(raw).expect("bad ACPI RSDP");
        let (root, xsdt) = match rsdp.xsdt {
            Some(x) => (table_at(x, Some(b"XSDT")), true),
            None => (table_at(u64::from(rsdp.rsdt), Some(b"RSDT")), false),
        };
        let root = root.expect("no valid ACPI root table");

        let mut info = Info::default();
        for addr in slate_acpi::root_entries(root, xsdt) {
            let Some(t) = table_at(addr, None) else { continue };
            info.tables.push(Table::new(addr, t));
            match &t[..4] {
                b"APIC" => parse_madt(t, &mut info),
                b"HPET" => info.hpet = slate_acpi::hpet::parse(t).map(|h| h.base),
                b"FACP" => info.fadt = fadt::parse(t),
                b"MCFG" => info.mcfg.extend(slate_acpi::mcfg::entries(t)),
                _ => {}
            }
        }
        if let Some((phys, dsdt)) = info.fadt.and_then(|f| table_at(f.dsdt, Some(b"DSDT")).map(|t| (f.dsdt, t))) {
            info.s5 = slate_acpi::find_s5(dsdt);
            info.tables.push(Table::new(phys, dsdt));
        }
        use crate::arch::boot::RegionKind as K;
        info.ram = crate::arch::boot::memory_map()
            .filter(|r| {
                matches!(
                    r.kind,
                    K::Usable | K::BootloaderReclaimable | K::KernelAndModules | K::AcpiReclaimable | K::AcpiNvs
                )
            })
            .map(|r| (r.base, r.len))
            .collect();
        log_info!(
            "ACPI rev {}: {} CPUs, {} I/O APICs, HPET {}, \\_S5 {:?}",
            rsdp.revision,
            info.cpus.len(),
            info.io_apics.len(),
            if info.hpet.is_some() { "yes" } else { "no" },
            info.s5
        );
        info
    });
}

fn parse_madt(t: &[u8], info: &mut Info) {
    let Some(m) = madt::parse(t) else { return };
    info.local_apic_address = u64::from(m.local_apic_address);
    info.has_8259 = m.flags & madt::PCAT_COMPAT != 0;
    let usable = |flags: u32| flags & (madt::LAPIC_ENABLED | madt::LAPIC_ONLINE_CAPABLE) != 0;
    for e in m.entries() {
        match e {
            madt::Entry::LocalApic { processor_uid, apic_id, flags } if usable(flags) => {
                info.cpus.push(Cpu { processor_uid: u32::from(processor_uid), apic_id: u32::from(apic_id) })
            }
            madt::Entry::LocalX2Apic { x2apic_id, flags, processor_uid } if usable(flags) => {
                info.cpus.push(Cpu { processor_uid, apic_id: x2apic_id })
            }
            madt::Entry::IoApic { id, address, gsi_base } => {
                info.io_apics.push(IoApic { id, address: u64::from(address), gsi_base })
            }
            madt::Entry::SourceOverride { source, gsi, flags, .. } => {
                info.overrides.push(Override { source, gsi, flags })
            }
            madt::Entry::LocalApicNmi { lint, flags, .. } => info.nmi_lint = Some((lint, flags)),
            madt::Entry::LocalApicAddressOverride { address } => info.local_apic_address = address,
            _ => {}
        }
    }
}
