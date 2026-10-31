// SPDX-License-Identifier: MIT OR Apache-2.0

//! A simulated codec that answers the parameter and connection verbs from
//! a list of widgets and records every other verb (for the tests here and
//! the kernel's own).

use alloc::vec::Vec;

use crate::graph::{Codec, Widget};
use crate::verb::*;

#[derive(Debug)]
pub struct SimCodec {
    pub vendor: u32,
    pub afg: u8,
    pub widgets: Vec<Widget>,
    pub group_pcm: u32,
    pub group_amp_out: u32,
    pub group_amp_in: u32,
    /// Verbs that set something, in order.
    pub sets: Vec<u32>,
}

impl SimCodec {
    fn widget(&self, nid: u8) -> Option<&Widget> {
        self.widgets.iter().find(|w| w.nid == nid)
    }
}

impl Codec for SimCodec {
    fn cmd(&mut self, v: u32) -> Option<u32> {
        let nid = ((v >> 20) & 0xff) as u8;
        let verb12 = ((v >> 8) & 0xfff) as u16;
        let payload = (v & 0xff) as u8;
        if verb12 == GET_PARAMETER {
            return Some(match (nid, payload) {
                (0, PARAM_VENDOR_ID) => self.vendor,
                (0, PARAM_SUBORDINATE_COUNT) => (u32::from(self.afg) << 16) | 1,
                (n, PARAM_FUNCTION_GROUP_TYPE) if n == self.afg => FG_AUDIO,
                (n, PARAM_SUBORDINATE_COUNT) if n == self.afg => {
                    let first = self.widgets.iter().map(|w| w.nid).min().unwrap_or(0);
                    let last = self.widgets.iter().map(|w| w.nid).max().unwrap_or(0);
                    (u32::from(first) << 16) | u32::from(last - first + 1)
                }
                (n, PARAM_PCM) if n == self.afg => self.group_pcm,
                (n, PARAM_STREAM_FORMATS) if n == self.afg => 1,
                (n, PARAM_AMP_OUT_CAPS) if n == self.afg => self.group_amp_out,
                (n, PARAM_AMP_IN_CAPS) if n == self.afg => self.group_amp_in,
                (n, p) => {
                    let w = self.widget(n)?;
                    match p {
                        PARAM_AUDIO_WIDGET_CAPS => w.caps,
                        PARAM_PIN_CAPS => w.pin_caps,
                        PARAM_CONNECTION_LIST_LENGTH => w.conns.len() as u32,
                        PARAM_PCM => w.pcm,
                        PARAM_STREAM_FORMATS => w.formats,
                        PARAM_AMP_OUT_CAPS => w.amp_out.0,
                        PARAM_AMP_IN_CAPS => w.amp_in.0,
                        _ => 0,
                    }
                }
            });
        }
        if verb12 == GET_CONNECTION_LIST {
            let w = self.widget(nid)?;
            let mut r = 0u32;
            for k in 0..4 {
                if let Some(&c) = w.conns.get(payload as usize + k) {
                    r |= u32::from(c) << (8 * k);
                }
            }
            return Some(r);
        }
        if verb12 == GET_CONFIG_DEFAULT {
            return self.widget(nid).map(|w| w.config);
        }
        self.sets.push(v);
        Some(0)
    }
}

/// Widget capabilities for a widget of `kind` with the given bits.
pub fn caps(kind: u32, bits: u32) -> u32 {
    (kind << 20) | bits
}

/// A configuration default: connectivity (0 jack, 1 none, 2 fixed), the
/// default device, association and sequence.
pub fn config(port: u32, device: u32, assoc: u32, seq: u32) -> u32 {
    (port << 30) | (device << 20) | (assoc << 4) | seq
}
