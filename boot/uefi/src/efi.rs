// SPDX-License-Identifier: MIT OR Apache-2.0

//! The UEFI interfaces the loader calls, from the UEFI Specification 2.10:
//! the system table (§4.3), boot services (§4.4, §7), runtime services'
//! GetTime (§8.3), the console protocols (§12.3, §12.4), the loaded image
//! (§9.1), device paths (§10), image loading (§7.4), simple file system
//! and file protocols (§13.4, §13.5) and the graphics output protocol
//! (§12.9). Function slots the loader never
//! calls are plain words.

use core::ffi::c_void;

pub type Handle = *mut c_void;
pub type Event = *mut c_void;
pub type Status = usize;

pub const SUCCESS: Status = 0;
const ERROR_BIT: usize = 1 << 63;
pub const INVALID_PARAMETER: Status = ERROR_BIT | 2;

pub fn is_error(s: Status) -> bool {
    s & ERROR_BIT != 0
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guid(pub u32, pub u16, pub u16, pub [u8; 8]);

pub const LOADED_IMAGE: Guid = Guid(0x5b1b_31a1, 0x9562, 0x11d2, [0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b]);
pub const SIMPLE_FILE_SYSTEM: Guid =
    Guid(0x964e_5b22, 0x6459, 0x11d2, [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b]);
/// EFI_DEVICE_PATH_PROTOCOL (§10.2).
pub const DEVICE_PATH: Guid = Guid(0x0957_6e91, 0x6d3f, 0x11d2, [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b]);
pub const GRAPHICS_OUTPUT: Guid = Guid(0x9042_a9de, 0x23dc, 0x4a38, [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a]);
/// The display's EDID as in use, and as read (§12.9.3,
/// EFI_EDID_ACTIVE_PROTOCOL and EFI_EDID_DISCOVERED_PROTOCOL).
pub const EDID_ACTIVE: Guid = Guid(0xbd8c_1056, 0x9f36, 0x44ec, [0x92, 0xa8, 0xa6, 0x33, 0x7f, 0x81, 0x79, 0x86]);
pub const EDID_DISCOVERED: Guid = Guid(0x1c0c_34f6, 0xd380, 0x41fa, [0xa0, 0x49, 0x8a, 0xd0, 0x6c, 0x1a, 0x66, 0xaa]);
/// Blt's copy from a buffer to the screen (§12.9.2, EfiBltBufferToVideo).
pub const BLT_BUFFER_TO_VIDEO: u32 = 2;
/// LocateHandleBuffer's search by protocol (§7.3.15, EFI_LOCATE_SEARCH_TYPE).
pub const BY_PROTOCOL: u32 = 2;
/// Configuration tables (§4.6): the ACPI 2.0 and 1.0 RSDPs.
pub const ACPI_20: Guid = Guid(0x8868_e871, 0xe4f1, 0x11d3, [0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81]);
pub const ACPI_10: Guid = Guid(0xeb9d_2d30, 0x2d88, 0x11d3, [0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d]);

#[repr(C)]
#[derive(Debug)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct SystemTable {
    pub hdr: TableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    pub console_in_handle: Handle,
    pub con_in: *mut SimpleTextInput,
    pub console_out_handle: Handle,
    pub con_out: *mut SimpleTextOutput,
    pub standard_error_handle: Handle,
    pub std_err: *mut SimpleTextOutput,
    pub runtime_services: *mut RuntimeServices,
    pub boot_services: *mut BootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: *const ConfigurationTable,
}

#[repr(C)]
#[derive(Debug)]
pub struct ConfigurationTable {
    pub guid: Guid,
    pub table: *const c_void,
}

#[repr(C)]
#[derive(Debug)]
pub struct InputKey {
    pub scan_code: u16,
    pub unicode_char: u16,
}

/// Scan codes (§12.3, table 12-1).
pub const SCAN_UP: u16 = 1;
pub const SCAN_DOWN: u16 = 2;
pub const SCAN_ESC: u16 = 0x17;

#[repr(C)]
#[derive(Debug)]
pub struct SimpleTextInput {
    pub reset: extern "efiapi" fn(*mut SimpleTextInput, bool) -> Status,
    pub read_key_stroke: extern "efiapi" fn(*mut SimpleTextInput, *mut InputKey) -> Status,
    pub wait_for_key: Event,
}

#[repr(C)]
#[derive(Debug)]
pub struct SimpleTextOutput {
    pub reset: extern "efiapi" fn(*mut SimpleTextOutput, bool) -> Status,
    pub output_string: extern "efiapi" fn(*mut SimpleTextOutput, *const u16) -> Status,
    pub test_string: usize,
    pub query_mode: extern "efiapi" fn(*mut SimpleTextOutput, usize, *mut usize, *mut usize) -> Status,
    pub set_mode: usize,
    pub set_attribute: extern "efiapi" fn(*mut SimpleTextOutput, usize) -> Status,
    pub clear_screen: extern "efiapi" fn(*mut SimpleTextOutput) -> Status,
    pub set_cursor_position: extern "efiapi" fn(*mut SimpleTextOutput, usize, usize) -> Status,
    pub enable_cursor: extern "efiapi" fn(*mut SimpleTextOutput, bool) -> Status,
    pub mode: *const TextMode,
}

/// SIMPLE_TEXT_OUTPUT_MODE (§12.4.1).
#[repr(C)]
#[derive(Debug)]
pub struct TextMode {
    pub max_mode: i32,
    pub mode: i32,
    pub attribute: i32,
    pub cursor_column: i32,
    pub cursor_row: i32,
    pub cursor_visible: bool,
}

/// Text attributes (§12.4.7): a foreground colour, and a background one
/// shifted left by four.
/// (slate_loader::textmenu has the others.)
pub const LIGHTGRAY: usize = 0x07;

/// EFI_TIME (§8.3).
#[repr(C)]
#[derive(Debug, Default)]
pub struct Time {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub pad1: u8,
    pub nanosecond: u32,
    pub time_zone: i16,
    pub daylight: u8,
    pub pad2: u8,
}

/// EFI_UNSPECIFIED_TIMEZONE: the time is local, zone unknown.
pub const UNSPECIFIED_TIMEZONE: i16 = 0x07ff;

#[repr(C)]
#[derive(Debug)]
pub struct RuntimeServices {
    pub hdr: TableHeader,
    pub get_time: extern "efiapi" fn(*mut Time, *mut c_void) -> Status,
}

/// Memory types (§7.2.3, table 7-6), and two of the range the
/// specification leaves to operating systems' loaders (0x80000000 and up)
/// for what the kernel must tell apart.
pub mod memory {
    pub const LOADER_CODE: u32 = 1;
    pub const LOADER_DATA: u32 = 2;
    pub const BOOT_SERVICES_CODE: u32 = 3;
    pub const BOOT_SERVICES_DATA: u32 = 4;
    pub const CONVENTIONAL: u32 = 7;
    pub const UNUSABLE: u32 = 8;
    pub const ACPI_RECLAIM: u32 = 9;
    pub const ACPI_NVS: u32 = 10;
    /// What the loader asks for (both allocated as loader data, the
    /// kernel's ranges remembered): its own data the kernel gets
    /// (responses, tables, stacks), and the kernel's image and modules.
    pub const SLATE_LOADER: u32 = 0x8000_0000;
    pub const SLATE_KERNEL: u32 = 0x8000_0001;
}

/// AllocatePages' kinds (§7.2.1).
pub const ALLOCATE_ANY_PAGES: u32 = 0;
pub const ALLOCATE_MAX_ADDRESS: u32 = 1;

#[repr(C)]
#[derive(Debug)]
pub struct BootServices {
    pub hdr: TableHeader,
    pub raise_tpl: usize,
    pub restore_tpl: usize,
    pub allocate_pages: extern "efiapi" fn(u32, u32, usize, *mut u64) -> Status,
    pub free_pages: extern "efiapi" fn(u64, usize) -> Status,
    pub get_memory_map: extern "efiapi" fn(*mut usize, *mut u8, *mut usize, *mut usize, *mut u32) -> Status,
    pub allocate_pool: extern "efiapi" fn(u32, usize, *mut *mut u8) -> Status,
    pub free_pool: extern "efiapi" fn(*mut u8) -> Status,
    pub create_event: usize,
    pub set_timer: usize,
    pub wait_for_event: usize,
    pub signal_event: usize,
    pub close_event: usize,
    pub check_event: usize,
    pub install_protocol_interface: usize,
    pub reinstall_protocol_interface: usize,
    pub uninstall_protocol_interface: usize,
    pub handle_protocol: extern "efiapi" fn(Handle, *const Guid, *mut *mut c_void) -> Status,
    pub reserved: usize,
    pub register_protocol_notify: usize,
    pub locate_handle: usize,
    pub locate_device_path: usize,
    pub install_configuration_table: usize,
    /// LoadImage (§7.4.1): boot policy, parent, device path, source
    /// buffer and its size, the new image's handle.
    pub load_image: extern "efiapi" fn(bool, Handle, *const u8, *const u8, usize, *mut Handle) -> Status,
    /// StartImage (§7.4.2): exit data's size and the exit data.
    pub start_image: extern "efiapi" fn(Handle, *mut usize, *mut *mut u16) -> Status,
    pub exit: usize,
    pub unload_image: usize,
    pub exit_boot_services: extern "efiapi" fn(Handle, usize) -> Status,
    pub get_next_monotonic_count: usize,
    pub stall: extern "efiapi" fn(usize) -> Status,
    pub set_watchdog_timer: extern "efiapi" fn(usize, u64, usize, *const u16) -> Status,
    pub connect_controller: usize,
    pub disconnect_controller: usize,
    pub open_protocol: usize,
    pub close_protocol: usize,
    pub open_protocol_information: usize,
    pub protocols_per_handle: usize,
    pub locate_handle_buffer: extern "efiapi" fn(u32, *const Guid, *mut c_void, *mut usize, *mut *mut Handle) -> Status,
    pub locate_protocol: extern "efiapi" fn(*const Guid, *mut c_void, *mut *mut c_void) -> Status,
}

#[repr(C)]
#[derive(Debug)]
pub struct LoadedImage {
    pub revision: u32,
    pub parent_handle: Handle,
    pub system_table: *mut SystemTable,
    pub device_handle: Handle,
    pub file_path: *const c_void,
    pub reserved: *const c_void,
    pub load_options_size: u32,
    pub load_options: *const c_void,
    pub image_base: *const c_void,
    pub image_size: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct SimpleFileSystem {
    pub revision: u64,
    pub open_volume: extern "efiapi" fn(*mut SimpleFileSystem, *mut *mut File) -> Status,
}

pub const FILE_MODE_READ: u64 = 1;
pub const FILE_MODE_WRITE: u64 = 2;

#[repr(C)]
#[derive(Debug)]
pub struct File {
    pub revision: u64,
    pub open: extern "efiapi" fn(*mut File, *mut *mut File, *const u16, u64, u64) -> Status,
    pub close: extern "efiapi" fn(*mut File) -> Status,
    pub delete: usize,
    pub read: extern "efiapi" fn(*mut File, *mut usize, *mut u8) -> Status,
    pub write: extern "efiapi" fn(*mut File, *mut usize, *const u8) -> Status,
    pub get_position: extern "efiapi" fn(*mut File, *mut u64) -> Status,
    pub set_position: extern "efiapi" fn(*mut File, u64) -> Status,
    pub get_info: usize,
    pub set_info: usize,
    pub flush: extern "efiapi" fn(*mut File) -> Status,
}

/// Pixel formats (§12.9, EFI_GRAPHICS_PIXEL_FORMAT).
pub const PIXEL_RGB: u32 = 0;
pub const PIXEL_BGR: u32 = 1;
pub const PIXEL_BITMASK: u32 = 2;

#[repr(C)]
#[derive(Debug)]
pub struct ModeInformation {
    pub version: u32,
    pub horizontal_resolution: u32,
    pub vertical_resolution: u32,
    pub pixel_format: u32,
    pub red_mask: u32,
    pub green_mask: u32,
    pub blue_mask: u32,
    pub reserved_mask: u32,
    pub pixels_per_scan_line: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct GraphicsMode {
    pub max_mode: u32,
    pub mode: u32,
    pub info: *const ModeInformation,
    pub size_of_info: usize,
    pub frame_buffer_base: u64,
    pub frame_buffer_size: usize,
}

#[repr(C)]
#[derive(Debug)]
pub struct GraphicsOutput {
    pub query_mode: extern "efiapi" fn(*mut GraphicsOutput, u32, *mut usize, *mut *mut ModeInformation) -> Status,
    pub set_mode: extern "efiapi" fn(*mut GraphicsOutput, u32) -> Status,
    /// Blt (§12.9.2): buffer, operation, source x and y, destination x
    /// and y, width, height, the buffer's bytes a line (0: width × 4).
    #[allow(clippy::type_complexity)]
    pub blt: extern "efiapi" fn(
        *mut GraphicsOutput,
        *mut u32,
        u32,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
    ) -> Status,
    pub mode: *const GraphicsMode,
}

/// EFI_EDID_ACTIVE_PROTOCOL / EFI_EDID_DISCOVERED_PROTOCOL (§12.9.3).
#[repr(C)]
#[derive(Debug)]
pub struct Edid {
    pub size_of_edid: u32,
    pub edid: *const u8,
}

/// Device path nodes (§10.2, §10.3): a type, a sub-type and the node's
/// length in bytes, then its data.
pub mod path {
    pub const MEDIA: u8 = 4;
    /// Hard drive media (§10.3.5.1): partition number, start, size, the
    /// signature at 24, the MBR type at 40 and the signature's type at 41
    /// (2: a GPT unique GUID); 42 bytes.
    pub const HARD_DRIVE: u8 = 1;
    pub const SIGNATURE_GUID: u8 = 2;
    /// A file's path on the media (§10.3.5.4): UCS-2, NUL-terminated.
    pub const FILE: u8 = 4;
    pub const END: u8 = 0x7F;
    pub const END_ENTIRE: u8 = 0xFF;
}

/// EFI_MEMORY_DESCRIPTOR's fields at their offsets (§7.2.3); the firmware
/// gives the descriptor's size, which may be larger.
pub fn descriptor(d: &[u8]) -> (u32, u64, u64) {
    let u64_at = |o: usize| u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
    (u32::from_le_bytes(d[0..4].try_into().unwrap()), u64_at(8), u64_at(24))
}
