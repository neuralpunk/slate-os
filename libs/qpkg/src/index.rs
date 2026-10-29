// SPDX-License-Identifier: MIT OR Apache-2.0

//! A repository's `INDEX` (ADR 0025): `quarry-index 1`, then one paragraph
//! per package. `INDEX.sig` is a detached signature record over it.

use alloc::string::String;
use alloc::vec::Vec;

use crate::Error;
use crate::manifest::Manifest;

pub const HEADER: &str = "quarry-index 1";

pub fn parse(text: &str) -> Result<Vec<Manifest>, Error> {
    let body = text.strip_prefix(HEADER).ok_or(Error::Format("not a quarry index"))?;
    let mut out = Vec::new();
    let mut para = String::new();
    for line in body.lines().chain(core::iter::once("")) {
        if line.trim().is_empty() {
            if !para.trim().is_empty() {
                let m = Manifest::parse(&para)?;
                if m.file.is_empty() || m.sha256.len() != 64 || !crate::archive::valid_path(&m.file) {
                    return Err(Error::Format("index entry needs file and sha256"));
                }
                out.push(m);
            }
            para.clear();
        } else {
            para.push_str(line);
            para.push('\n');
        }
    }
    Ok(out)
}

pub fn to_text(packages: &[Manifest]) -> String {
    let mut s = String::from(HEADER);
    s.push('\n');
    for m in packages {
        s.push('\n');
        s.push_str(&m.to_text());
    }
    s
}
