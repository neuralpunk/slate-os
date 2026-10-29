// SPDX-License-Identifier: MIT OR Apache-2.0

//! Personal data files (M28, ADR 0109): iCalendar (RFC 5545) for
//! calendars and vCard (RFC 6350) for contacts, over the content lines
//! both share, read leniently and written to the standards, keeping
//! what they don't understand.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod date;
pub mod ical;
pub mod line;
pub mod vcard;
