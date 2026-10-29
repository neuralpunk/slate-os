// SPDX-License-Identifier: MIT OR Apache-2.0

//! UEFI runtime services (ADR 0088): the variable services, called in an
//! address space of their own.
//!
//! Sources: the UEFI Specification 2.10: the system table (§4.3) and the
//! runtime services table (§4.5); the memory map's descriptors and the
//! `EFI_MEMORY_RUNTIME` attribute (§7.2.3); GetVariable,
//! GetNextVariableName and SetVariable (§8.2). Limine does not call
//! SetVirtualAddressMap, so the services expect the memory they use at
//! its physical addresses: the lower half of the address space they run
//! in maps every runtime region one to one, and one buffer for the
//! arguments.

use alloc::vec::Vec;

use super::paging::{CacheMode, MapFlags, Mapper};
use crate::drivers::dma::Dma;
use crate::mm::PhysAddr;
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

/// EFI_MEMORY_RUNTIME (§7.2.3, the memory map's Attribute field).
const MEMORY_RUNTIME: u64 = 1 << 63;
/// EfiMemoryMappedIO and EfiMemoryMappedIOPortSpace (§7.2.3, table 7-6).
const MEMORY_MAPPED_IO: u32 = 11;
const MEMORY_MAPPED_IO_PORT_SPACE: u32 = 12;
/// "RUNTSERV", the runtime services table's signature (§4.5).
const RUNTIME_SIGNATURE: u64 = 0x5652_4553_544E_5552;
/// Offsets in the runtime services table (§4.5.1): GetVariable,
/// GetNextVariableName, SetVariable.
const GET_VARIABLE: usize = 72;
const GET_NEXT_VARIABLE_NAME: usize = 80;
const SET_VARIABLE: usize = 88;

/// The high bit of an EFI_STATUS marks an error (appendix D).
const ERROR_BIT: u64 = 1 << 63;
pub const NOT_FOUND: u64 = ERROR_BIT | 14;

/// Layout of the argument buffer: the name (UCS-2, at most 1024 units),
/// the GUID, the size, the attributes, then the data.
const NAME_AT: usize = 0;
const NAME_UNITS: usize = 1024;
const GUID_AT: usize = 2048;
const SIZE_AT: usize = 2064;
const ATTRS_AT: usize = 2072;
const DATA_AT: usize = 4096;
const BUFFER: usize = 64 << 10;
/// The largest variable this reads or writes.
pub const MAX_DATA: usize = BUFFER - DATA_AT;

/// What a call failed with: the EFI_STATUS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status(pub u64);

struct Runtime {
    root: PhysAddr,
    buf: Dma,
    get_variable: u64,
    get_next: u64,
    set_variable: u64,
}

static RUNTIME: IrqSpinLock<Option<Runtime>> = IrqSpinLock::new(None);

/// Set the runtime services up from the memory map (`desc_size`-byte
/// descriptors, as the boot loader gave it) and the runtime services
/// table's physical address. Logs and leaves them off on anything odd.
pub fn init(memmap: &[u8], desc_size: usize, runtime_table: u64) {
    if desc_size < 40 || runtime_table == 0 {
        return;
    }
    let Some(mut m) = Mapper::new_user() else { return };
    let mut regions = 0;
    for d in memmap.chunks_exact(desc_size) {
        let u32_at = |o: usize| u32::from_le_bytes(d[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
        // EFI_MEMORY_DESCRIPTOR: Type, (pad), PhysicalStart, VirtualStart,
        // NumberOfPages, Attribute.
        let (kind, start, pages, attr) = (u32_at(0), u64_at(8), u64_at(24), u64_at(32));
        if attr & MEMORY_RUNTIME == 0 || pages == 0 {
            continue;
        }
        let io = matches!(kind, MEMORY_MAPPED_IO | MEMORY_MAPPED_IO_PORT_SPACE);
        let flags = MapFlags {
            write: true,
            exec: !io,
            user: false,
            // Never global: these addresses mean user memory everywhere
            // else.
            global: false,
            cache: if io { CacheMode::Uncached } else { CacheMode::WriteBack },
        };
        if let Err(e) = m.map_range(start, PhysAddr(start), pages * 4096, flags) {
            log_warn!("efi: cannot map the runtime region at {start:#x} ({e:?}); no runtime services");
            return;
        }
        regions += 1;
    }
    let Some(buf) = Dma::new(BUFFER) else { return };
    let data = MapFlags { write: true, exec: false, user: false, global: false, cache: CacheMode::WriteBack };
    if m.map_range(buf.phys(), PhysAddr(buf.phys()), buf.len() as u64, data).is_err() {
        log_warn!("efi: cannot map the argument buffer; no runtime services");
        return;
    }
    // The table and the services' addresses, through the direct map.
    super::paging::ensure_direct_mapped(runtime_table, 136);
    let table = PhysAddr(runtime_table).to_virt().cast::<u64>();
    // SAFETY: The runtime services table is firmware memory the boot
    // loader reported, mapped in the direct map just above; it is read
    // once, at 8-byte offsets inside its 136 bytes (§4.5).
    let word = |o: usize| unsafe { core::ptr::read_volatile(table.byte_add(o)) };
    if word(0) != RUNTIME_SIGNATURE {
        log_warn!("efi: the runtime services table at {runtime_table:#x} has no RUNTSERV signature");
        return;
    }
    let rt = Runtime {
        root: m.root(),
        buf,
        get_variable: word(GET_VARIABLE),
        get_next: word(GET_NEXT_VARIABLE_NAME),
        set_variable: word(SET_VARIABLE),
    };
    log_info!("efi: runtime services at {runtime_table:#x}, {regions} runtime regions");
    *RUNTIME.lock() = Some(rt);
}

/// Whether the variable services can be called.
pub fn available() -> bool {
    RUNTIME.lock().is_some()
}

/// Run `f` with the runtime services' address space loaded, interrupts
/// masked and the vector registers saved (the firmware may use SSE).
fn with_runtime<R>(f: impl FnOnce(&Runtime) -> R) -> Option<R> {
    let g = RUNTIME.lock();
    let rt = g.as_ref()?;
    Some(super::fpu::with_vectors(|| {
        let old = PhysAddr(super::cpu::read_cr3() & 0x000F_FFFF_FFFF_F000);
        super::paging::switch_root(rt.root);
        let r = f(rt);
        super::paging::switch_root(old);
        r
    }))
}

fn put_name(rt: &Runtime, name: &[u16]) -> Option<()> {
    if name.len() >= NAME_UNITS {
        return None;
    }
    for (i, u) in name.iter().chain(core::iter::once(&0)).enumerate() {
        rt.buf.write::<u16>(NAME_AT + 2 * i, *u);
    }
    Some(())
}

type GetVariable = extern "efiapi" fn(u64, u64, u64, u64, u64) -> u64;
type GetNextVariableName = extern "efiapi" fn(u64, u64, u64) -> u64;
type SetVariable = extern "efiapi" fn(u64, u64, u32, u64, u64) -> u64;

// Calls into the firmware: its code has no KCFI type tags, so these calls
// alone are not checked (ADR 0096).
#[sanitize(kcfi = "off")]
fn call_get_variable(f: GetVariable, a: u64, b: u64, c: u64, d: u64, e: u64) -> u64 {
    f(a, b, c, d, e)
}

#[sanitize(kcfi = "off")]
fn call_get_next(f: GetNextVariableName, a: u64, b: u64, c: u64) -> u64 {
    f(a, b, c)
}

#[sanitize(kcfi = "off")]
fn call_set_variable(f: SetVariable, a: u64, b: u64, c: u32, d: u64, e: u64) -> u64 {
    f(a, b, c, d, e)
}

/// GetVariable: a variable's attributes and data.
pub fn get_variable(name: &[u16], guid: &[u8; 16]) -> Result<(u32, Vec<u8>), Status> {
    with_runtime(|rt| {
        put_name(rt, name).ok_or(Status(ERROR_BIT | 2))?;
        rt.buf.copy_in(GUID_AT, guid);
        rt.buf.write::<u64>(SIZE_AT, MAX_DATA as u64);
        rt.buf.write::<u32>(ATTRS_AT, 0);
        let p = rt.buf.phys();
        // SAFETY: GetVariable's address came from the firmware's runtime
        // services table; it runs in the address space that maps its
        // regions and the buffer one to one, with the pointers into the
        // buffer it expects (§8.2.1).
        let f: GetVariable = unsafe { core::mem::transmute::<u64, GetVariable>(rt.get_variable) };
        let s = call_get_variable(
            f,
            p + NAME_AT as u64,
            p + GUID_AT as u64,
            p + ATTRS_AT as u64,
            p + SIZE_AT as u64,
            p + DATA_AT as u64,
        );
        if s & ERROR_BIT != 0 {
            return Err(Status(s));
        }
        let size = (rt.buf.read::<u64>(SIZE_AT) as usize).min(MAX_DATA);
        let mut data = alloc::vec![0u8; size];
        rt.buf.copy_out(DATA_AT, &mut data);
        Ok((rt.buf.read::<u32>(ATTRS_AT), data))
    })
    .unwrap_or(Err(Status(ERROR_BIT | 3)))
}

/// A variable's name (UCS-2, without the NUL) and vendor GUID.
pub type Variable = (Vec<u16>, [u8; 16]);

/// GetNextVariableName: the variable after `prev` (None: the first), or
/// None at the end.
pub fn next_variable(prev: Option<(&[u16], &[u8; 16])>) -> Result<Option<Variable>, Status> {
    with_runtime(|rt| {
        match prev {
            Some((name, guid)) => {
                put_name(rt, name).ok_or(Status(ERROR_BIT | 2))?;
                rt.buf.copy_in(GUID_AT, guid);
            }
            None => {
                rt.buf.write::<u16>(NAME_AT, 0);
                rt.buf.copy_in(GUID_AT, &[0; 16]);
            }
        }
        rt.buf.write::<u64>(SIZE_AT, (NAME_UNITS * 2) as u64);
        let p = rt.buf.phys();
        // SAFETY: As for GetVariable (§8.2.2).
        let f: GetNextVariableName = unsafe { core::mem::transmute::<u64, GetNextVariableName>(rt.get_next) };
        let s = call_get_next(f, p + SIZE_AT as u64, p + NAME_AT as u64, p + GUID_AT as u64);
        if s == NOT_FOUND {
            return Ok(None);
        }
        if s & ERROR_BIT != 0 {
            return Err(Status(s));
        }
        let mut name = Vec::new();
        for i in 0..NAME_UNITS {
            let u = rt.buf.read::<u16>(NAME_AT + 2 * i);
            if u == 0 {
                break;
            }
            name.push(u);
        }
        let mut guid = [0u8; 16];
        rt.buf.copy_out(GUID_AT, &mut guid);
        Ok(Some((name, guid)))
    })
    .unwrap_or(Err(Status(ERROR_BIT | 3)))
}

/// SetVariable: write a variable, or delete it with no data (§8.2.3).
pub fn set_variable(name: &[u16], guid: &[u8; 16], attrs: u32, data: &[u8]) -> Result<(), Status> {
    if data.len() > MAX_DATA {
        return Err(Status(ERROR_BIT | 9));
    }
    with_runtime(|rt| {
        put_name(rt, name).ok_or(Status(ERROR_BIT | 2))?;
        rt.buf.copy_in(GUID_AT, guid);
        rt.buf.copy_in(DATA_AT, data);
        let p = rt.buf.phys();
        // SAFETY: As for GetVariable.
        let f: SetVariable = unsafe { core::mem::transmute::<u64, SetVariable>(rt.set_variable) };
        let s =
            call_set_variable(f, p + NAME_AT as u64, p + GUID_AT as u64, attrs, data.len() as u64, p + DATA_AT as u64);
        if s & ERROR_BIT != 0 { Err(Status(s)) } else { Ok(()) }
    })
    .unwrap_or(Err(Status(ERROR_BIT | 3)))
}
