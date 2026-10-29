// SPDX-License-Identifier: MIT OR Apache-2.0

//! The probe against volumes Slate's own writers make.

use slate_fsprobe::{Kind, PROBE_BYTES, probe};

struct Mem(Vec<u8>);

impl slatefs::Disk for Mem {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> slatefs::Result<()> {
        let o = offset as usize;
        buf.copy_from_slice(&self.0[o..o + buf.len()]);
        Ok(())
    }
    fn write(&mut self, offset: u64, buf: &[u8]) -> slatefs::Result<()> {
        let o = offset as usize;
        self.0[o..o + buf.len()].copy_from_slice(buf);
        Ok(())
    }
    fn flush(&mut self) -> slatefs::Result<()> {
        Ok(())
    }
    fn now(&self) -> (i64, u32) {
        (1_792_879_170, 0)
    }
}

#[test]
fn fat32_and_slatefs() {
    let bytes = 64u64 << 20;
    let mut img = vec![0u8; bytes as usize];
    slate_fat::write(&slate_fat::Volume::new(), bytes, "STICK", 0x1234_5678, 2048, &mut img).unwrap();
    let f = probe(&img[..PROBE_BYTES]).unwrap();
    assert_eq!((f.kind, f.label.as_str(), f.uuid.as_str()), (Kind::Fat32, "STICK", "1234-5678"));
    let uuid = [0xab; 16];
    let fs = slatefs::mkfs(Mem(vec![0u8; bytes as usize]), bytes / 4096, "data", uuid, "home").unwrap();
    let disk = fs.into_disk();
    let f = probe(&disk.0[..PROBE_BYTES]).unwrap();
    assert_eq!((f.kind, f.label.as_str()), (Kind::SlateFs, "data"));
    assert_eq!(f.uuid, "abababab-abab-abab-abab-abababababab");
}
