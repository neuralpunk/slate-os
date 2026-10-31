// SPDX-License-Identifier: MIT OR Apache-2.0

//! Codec verbs and parameters. Source: Intel's High Definition Audio
//! Specification, revision 1.0a (2010): §7.3 (the verb format: codec
//! address in bits 31:28, node ID 27:20, then a 12-bit verb with an 8-bit
//! payload or a 4-bit verb with a 16-bit payload), §7.3.3 (each verb),
//! §7.3.4 (the parameters).

/// A 12-bit verb with an 8-bit payload.
pub const fn verb12(cad: u8, nid: u8, verb: u16, payload: u8) -> u32 {
    ((cad as u32 & 0xf) << 28) | ((nid as u32) << 20) | ((verb as u32 & 0xfff) << 8) | payload as u32
}

/// A 4-bit verb with a 16-bit payload.
pub const fn verb4(cad: u8, nid: u8, verb: u8, payload: u16) -> u32 {
    ((cad as u32 & 0xf) << 28) | ((nid as u32) << 20) | ((verb as u32 & 0xf) << 16) | payload as u32
}

// 12-bit verbs (§7.3.3).
pub const GET_PARAMETER: u16 = 0xF00;
pub const GET_CONNECTION_SELECT: u16 = 0xF01;
pub const SET_CONNECTION_SELECT: u16 = 0x701;
pub const GET_CONNECTION_LIST: u16 = 0xF02;
pub const SET_POWER_STATE: u16 = 0x705;
pub const SET_CONVERTER_STREAM: u16 = 0x706;
pub const SET_PIN_CONTROL: u16 = 0x707;
pub const GET_PIN_SENSE: u16 = 0xF09;
pub const SET_EAPD: u16 = 0x70C;
pub const GET_CONFIG_DEFAULT: u16 = 0xF1C;
pub const FUNCTION_RESET: u16 = 0x7FF;
// 4-bit verbs.
pub const SET_CONVERTER_FORMAT: u8 = 0x2;
pub const SET_AMP_GAIN_MUTE: u8 = 0x3;
pub const GET_AMP_GAIN_MUTE: u8 = 0xB;

// Parameters (§7.3.4).
pub const PARAM_VENDOR_ID: u8 = 0x00;
pub const PARAM_REVISION_ID: u8 = 0x02;
pub const PARAM_SUBORDINATE_COUNT: u8 = 0x04;
pub const PARAM_FUNCTION_GROUP_TYPE: u8 = 0x05;
pub const PARAM_AUDIO_WIDGET_CAPS: u8 = 0x09;
pub const PARAM_PCM: u8 = 0x0A;
pub const PARAM_STREAM_FORMATS: u8 = 0x0B;
pub const PARAM_PIN_CAPS: u8 = 0x0C;
pub const PARAM_AMP_IN_CAPS: u8 = 0x0D;
pub const PARAM_CONNECTION_LIST_LENGTH: u8 = 0x0E;
pub const PARAM_AMP_OUT_CAPS: u8 = 0x12;

/// The audio function group's type (§7.3.4.4).
pub const FG_AUDIO: u32 = 0x01;

// Audio widget capabilities (§7.3.4.6): the type in bits 23:20.
pub const WIDGET_OUTPUT: u32 = 0x0;
pub const WIDGET_INPUT: u32 = 0x1;
pub const WIDGET_MIXER: u32 = 0x2;
pub const WIDGET_SELECTOR: u32 = 0x3;
pub const WIDGET_PIN: u32 = 0x4;
pub const CAP_STEREO: u32 = 1 << 0;
pub const CAP_IN_AMP: u32 = 1 << 1;
pub const CAP_OUT_AMP: u32 = 1 << 2;
pub const CAP_AMP_OVERRIDE: u32 = 1 << 3;
pub const CAP_FORMAT_OVERRIDE: u32 = 1 << 4;
pub const CAP_CONN_LIST: u32 = 1 << 8;
pub const CAP_DIGITAL: u32 = 1 << 9;
pub const CAP_POWER_CONTROL: u32 = 1 << 10;

// Pin capabilities (§7.3.4.9).
pub const PIN_PRESENCE_DETECT: u32 = 1 << 2;
pub const PIN_HEADPHONE_DRIVE: u32 = 1 << 3;
pub const PIN_OUTPUT: u32 = 1 << 4;
pub const PIN_INPUT: u32 = 1 << 5;
pub const PIN_VREF_80: u32 = 1 << 10;
pub const PIN_VREF_50: u32 = 1 << 9;
pub const PIN_HDMI: u32 = 1 << 7;
pub const PIN_DP: u32 = 1 << 24;
pub const PIN_EAPD: u32 = 1 << 16;

// Pin widget control (§7.3.3.13).
pub const PINCTL_HP_ENABLE: u8 = 1 << 7;
pub const PINCTL_OUT_ENABLE: u8 = 1 << 6;
pub const PINCTL_IN_ENABLE: u8 = 1 << 5;
pub const PINCTL_VREF_50: u8 = 0x1;
pub const PINCTL_VREF_80: u8 = 0x4;

/// EAPD/BTL enable (§7.3.3.16): bit 1, EAPD.
pub const EAPD_ENABLE: u8 = 1 << 1;

/// The pin's configuration default (§7.3.3.31): port connectivity in bits
/// 31:30 (01: nothing attached), default device in 23:20.
pub const PORT_NONE: u32 = 0x1;
pub const DEV_LINE_OUT: u32 = 0x0;
pub const DEV_SPEAKER: u32 = 0x1;
pub const DEV_HP_OUT: u32 = 0x2;
pub const DEV_SPDIF_OUT: u32 = 0x4;
pub const DEV_DIGITAL_OUT: u32 = 0x5;
pub const DEV_LINE_IN: u32 = 0x8;
pub const DEV_MIC_IN: u32 = 0xA;

// Amplifier gain/mute set payload (§7.3.3.7): output 15, input 14, left
// 13, right 12, index 11:8, mute 7, gain 6:0.
pub const AMP_SET_OUTPUT: u16 = 1 << 15;
pub const AMP_SET_INPUT: u16 = 1 << 14;
pub const AMP_SET_LEFT: u16 = 1 << 13;
pub const AMP_SET_RIGHT: u16 = 1 << 12;
pub const AMP_MUTE: u16 = 1 << 7;

/// An amplifier's capabilities (§7.3.4.10): mute capable 31, step size
/// 22:16 (in quarter dB, less one), number of steps 14:8 (the top gain
/// value), offset 6:0 (the gain value that is 0 dB).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AmpCaps(pub u32);

impl AmpCaps {
    pub fn mute(self) -> bool {
        self.0 & (1 << 31) != 0
    }
    pub fn steps(self) -> u32 {
        (self.0 >> 8) & 0x7f
    }
    pub fn offset(self) -> u32 {
        self.0 & 0x7f
    }
    /// Each step in hundredths of a dB.
    pub fn step_cdb(self) -> u32 {
        (((self.0 >> 16) & 0x7f) + 1) * 25
    }
}

/// The amplifier payload that sets `gain` and `mute` on both channels of
/// an output amplifier, or of input `index`.
pub fn amp_payload(output: bool, index: u8, gain: u32, mute: bool, left: bool, right: bool) -> u16 {
    let mut p = if output { AMP_SET_OUTPUT } else { AMP_SET_INPUT };
    if left {
        p |= AMP_SET_LEFT;
    }
    if right {
        p |= AMP_SET_RIGHT;
    }
    p |= u16::from(index & 0xf) << 8;
    if mute {
        p |= AMP_MUTE;
    }
    p | (gain as u16 & 0x7f)
}

/// The stream format word (§3.7.1): base rate 48 or 44.1 kHz in bit 14,
/// multiple 13:11, divisor 10:8, bits per sample 6:4, channels less one
/// 3:0. None for rates and sizes it can't say.
pub fn stream_format(rate: u32, bits: u32, channels: u32) -> Option<u16> {
    let (base, mult, div) = match rate {
        8000 => (0, 1, 6),
        11025 => (1, 1, 4),
        16000 => (0, 1, 3),
        22050 => (1, 1, 2),
        32000 => (0, 2, 3),
        44100 => (1, 1, 1),
        48000 => (0, 1, 1),
        88200 => (1, 2, 1),
        96000 => (0, 2, 1),
        176400 => (1, 4, 1),
        192000 => (0, 4, 1),
        _ => return None,
    };
    let b = match bits {
        8 => 0,
        16 => 1,
        20 => 2,
        24 => 3,
        32 => 4,
        _ => return None,
    };
    if !(1..=16).contains(&channels) {
        return None;
    }
    Some((base << 14) | ((mult - 1) << 11) | ((div - 1) << 8) | (b << 4) | (channels as u16 - 1))
}

/// The rates in a PCM sizes-and-rates parameter (§7.3.4.7, bits 11:0:
/// 8, 11.025, 16, 22.05, 32, 44.1, 48, 88.2, 96, 176.4, 192, 384 kHz).
pub fn pcm_rates(param: u32) -> impl Iterator<Item = u32> {
    const RATES: [u32; 12] = [8000, 11025, 16000, 22050, 32000, 44100, 48000, 88200, 96000, 176400, 192000, 384000];
    (0..12).filter(move |i| param >> i & 1 == 1).map(|i| RATES[i])
}

/// The sample sizes in the same parameter (bits 20:16: 8, 16, 20, 24, 32).
pub fn pcm_bits(param: u32) -> impl Iterator<Item = u32> {
    const BITS: [u32; 5] = [8, 16, 20, 24, 32];
    (0..5).filter(move |i| param >> (16 + i) & 1 == 1).map(|i| BITS[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbs_and_formats() {
        assert_eq!(verb12(0, 0, GET_PARAMETER, PARAM_VENDOR_ID), 0x000F_0000);
        assert_eq!(verb12(2, 0x14, SET_PIN_CONTROL, 0x40), 0x2147_0740);
        assert_eq!(verb4(0, 2, SET_CONVERTER_FORMAT, 0x11), 0x0022_0011);
        // 48 kHz, 16 bits, stereo (the specification's example layout).
        assert_eq!(stream_format(48000, 16, 2), Some(0x0011));
        assert_eq!(stream_format(44100, 24, 2), Some(0x4031));
        assert_eq!(stream_format(96000, 32, 2), Some(0x0841));
        assert_eq!(stream_format(12345, 16, 2), None);
        assert_eq!(pcm_rates(0x60).collect::<std::vec::Vec<_>>(), [44100, 48000]);
        assert_eq!(pcm_bits(0x000e_0000).collect::<std::vec::Vec<_>>(), [16, 20, 24]);
        let a = AmpCaps(0x8005_4a4a);
        assert!(a.mute());
        assert_eq!((a.steps(), a.offset(), a.step_cdb()), (0x4a, 0x4a, 150));
        assert_eq!(amp_payload(true, 0, 0x4a, false, true, true), 0xb04a);
        assert_eq!(amp_payload(false, 1, 0, true, true, true), 0x7180);
    }
}
