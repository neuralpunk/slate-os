// SPDX-License-Identifier: MIT OR Apache-2.0

//! Files on the loader's own partition, through the firmware's simple file
//! system protocol (UEFI 2.10 §13.4, §13.5).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::efi;

#[derive(Debug)]
pub struct Volume {
    root: *mut efi::File,
}

/// A file read into pages of its own.
pub use slate_loader::boot::File as Loaded;

/// `a/b/c` as the firmware names it: `\a\b\c`, UCS-2, NUL-terminated.
pub fn name(path: &str) -> Vec<u16> {
    core::iter::once('\\')
        .chain(path.chars().map(|c| if c == '/' { '\\' } else { c }))
        .collect::<String>()
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect()
}

impl Volume {
    pub fn open(fs: *mut efi::SimpleFileSystem) -> Result<Volume, String> {
        let mut root = core::ptr::null_mut();
        // SAFETY: The firmware's simple file system protocol.
        let s = unsafe { ((*fs).open_volume)(fs, &mut root) };
        if efi::is_error(s) {
            return Err(format!("cannot open the boot partition (status {s:#x})"));
        }
        Ok(Volume { root })
    }

    /// Open `path` and find its size (setting the position to the end, then
    /// reading it: §13.5.13).
    fn open_file(&self, path: &str) -> Result<(*mut efi::File, u64), String> {
        let mut f = core::ptr::null_mut();
        let n = name(path);
        // SAFETY: The root directory's file protocol; a NUL-terminated name.
        let s = unsafe { ((*self.root).open)(self.root, &mut f, n.as_ptr(), efi::FILE_MODE_READ, 0) };
        if efi::is_error(s) {
            return Err(format!("{path}: not found (status {s:#x})"));
        }
        let mut size = 0u64;
        // SAFETY: The file just opened.
        unsafe {
            ((*f).set_position)(f, u64::MAX);
            ((*f).get_position)(f, &mut size);
            ((*f).set_position)(f, 0);
        }
        Ok((f, size))
    }

    fn fill(f: *mut efi::File, path: &str, dst: *mut u8, len: u64) -> Result<(), String> {
        let mut done = 0u64;
        while done < len {
            // 1 MiB a call: some firmware's USB drivers want small reads.
            let mut n = (len - done).min(1 << 20) as usize;
            // SAFETY: `dst` has room for `len` bytes.
            let s = unsafe { ((*f).read)(f, &mut n, dst.add(done as usize)) };
            if efi::is_error(s) || n == 0 {
                // SAFETY: The file is open.
                unsafe { ((*f).close)(f) };
                return Err(format!("{path}: read error (status {s:#x})"));
            }
            done += n as u64;
        }
        // SAFETY: The file is open.
        unsafe { ((*f).close)(f) };
        Ok(())
    }

    /// Overwrite an existing file from its start with `data` (no longer
    /// than it: the loader's count only goes down).
    pub fn overwrite(&self, path: &str, data: &[u8]) -> Result<(), String> {
        let mut f = core::ptr::null_mut();
        let n = name(path);
        let mode = efi::FILE_MODE_READ | efi::FILE_MODE_WRITE;
        // SAFETY: The root directory's file protocol; a NUL-terminated name.
        let s = unsafe { ((*self.root).open)(self.root, &mut f, n.as_ptr(), mode, 0) };
        if efi::is_error(s) {
            return Err(format!("{path}: cannot open for writing (status {s:#x})"));
        }
        let mut len = data.len();
        // SAFETY: The file just opened; `data` is `len` bytes.
        let s = unsafe {
            ((*f).set_position)(f, 0);
            let s = ((*f).write)(f, &mut len, data.as_ptr());
            ((*f).flush)(f);
            ((*f).close)(f);
            s
        };
        if efi::is_error(s) || len != data.len() {
            return Err(format!("{path}: write error (status {s:#x})"));
        }
        Ok(())
    }

    /// A whole file, in the heap.
    pub fn read(&self, path: &str) -> Result<Vec<u8>, String> {
        let (f, size) = self.open_file(path)?;
        let mut v = alloc::vec![0u8; size as usize];
        Self::fill(f, path, v.as_mut_ptr(), size)?;
        Ok(v)
    }

    /// A whole file, in pages of memory type `kind`.
    pub fn read_to(&self, path: &str, kind: u32) -> Result<Loaded, String> {
        let (f, size) = self.open_file(path)?;
        let phys = crate::pages(kind, size.max(1), None)?;
        Self::fill(f, path, phys as *mut u8, size)?;
        Ok(Loaded { phys, len: size })
    }
}
