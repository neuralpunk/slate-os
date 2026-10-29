// SPDX-License-Identifier: MIT OR Apache-2.0

//! An interpreter for the ACPI Machine Language (ADR 0079), written from
//! the ACPI Specification 6.5: the namespace and its predefined objects
//! (chapter 5), ASL's meaning (chapter 19) and the AML grammar (chapter
//! 20). It does no I/O of its own: a [`Host`] reads and writes the
//! address spaces and sleeps, so everything is tested on the host.
//!
//! Loading a table runs its TermList (§20.2.5): the namespace is built as
//! the terms run, method bodies are kept to be parsed when called, and a
//! term that fails costs its enclosing scope, not the table.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod events;
mod exec;
mod name;
mod namespace;
pub mod resource;
mod value;

#[cfg(test)]
mod tests;

pub use exec::{Interpreter, Problem, eisa_id};
pub use name::{NameSeg, Path};
pub use namespace::{Field, FieldKind, Method, NodeId, Object, ROOT, Region};
pub use value::Value;

use alloc::string::String;

/// An operation region's address space (§19.6.100, RegionSpace).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Space {
    SystemMemory,
    SystemIo,
    PciConfig,
    EmbeddedControl,
    SmBus,
    Cmos,
    PciBar,
    Ipmi,
    Gpio,
    SerialBus,
    Pcc,
    Other(u8),
}

impl Space {
    pub fn from_byte(b: u8) -> Space {
        match b {
            0 => Space::SystemMemory,
            1 => Space::SystemIo,
            2 => Space::PciConfig,
            3 => Space::EmbeddedControl,
            4 => Space::SmBus,
            5 => Space::Cmos,
            6 => Space::PciBar,
            7 => Space::Ipmi,
            8 => Space::Gpio,
            9 => Space::SerialBus,
            10 => Space::Pcc,
            b => Space::Other(b),
        }
    }
}

/// Where an access goes: an address in a space (for PCI configuration
/// space, the function's segment, bus, device and function, and the
/// register's offset).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Address {
    Memory(u64),
    Io(u16),
    Pci {
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        offset: u16,
    },
    /// Another space, and the offset in it.
    Other(Space, u64),
}

/// What AML needs from the system around it.
pub trait Host {
    /// Read `width` bits (8, 16, 32 or 64) at `at`.
    fn read(&mut self, at: Address, width: u8) -> Result<u64>;
    /// Write `width` bits at `at`.
    fn write(&mut self, at: Address, width: u8, value: u64) -> Result<()>;
    /// Stall (busy-wait) for `us` microseconds (§19.6.129).
    fn stall(&mut self, _us: u64) {}
    /// Sleep for `ms` milliseconds (§19.6.126).
    fn sleep(&mut self, _ms: u64) {}
    /// The 100 ns timer (§19.6.138).
    fn timer(&mut self) -> u64 {
        0
    }
    /// Notify(object, value) (§5.6.6).
    fn notify(&mut self, _path: &str, _value: u64) {}
    /// A Store to the Debug object.
    fn debug(&mut self, _text: &str) {}
    /// The physical address and length of the table DataRegion asks for
    /// (signature, OEM ID, OEM table ID).
    fn find_table(&mut self, _sig: &[u8], _oem: &[u8], _table: &[u8]) -> Option<(u64, u64)> {
        None
    }
}

/// What went wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The AML ended in the middle of something.
    Truncated,
    /// An opcode this interpreter does not know (extended ones as
    /// 0x5Bxx).
    BadOpcode(u16),
    /// A name that is not in the namespace.
    NotFound(String),
    /// A name defined twice in one scope.
    Exists(String),
    /// An object of the wrong kind for the operation.
    BadType(&'static str),
    /// Division (or Mod) by zero.
    DivideByZero,
    /// An index past the end of a buffer, package or string.
    OutOfRange,
    /// The host could not do an access.
    Host(&'static str),
    /// Something the interpreter does not do (yet).
    Unsupported(&'static str),
    /// Fatal (§19.6.48): type, code, argument.
    Fatal(u8, u32, u64),
    /// A loop ran too long or calls went too deep.
    Limit(&'static str),
}

pub type Result<T> = core::result::Result<T, Error>;
