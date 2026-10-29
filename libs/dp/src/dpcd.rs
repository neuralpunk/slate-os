// SPDX-License-Identifier: MIT OR Apache-2.0

//! The DisplayPort Configuration Data addresses a source reads and
//! writes over AUX (VESA DisplayPort Standard 1.4a, §2.9.3, "DPCD": the
//! Receiver Capability field from 00000h, Link Configuration from 00100h,
//! Link/Sink Device Status from 00200h, Sink Control at 00600h and the
//! Extended Receiver Capability field at 02200h).

/// DPCD_REV: the DPCD version, 10h for 1.0 up to 14h for 1.4.
pub const DPCD_REV: u32 = 0x00000;
/// MAX_LINK_RATE, in units of 0.27 Gbps per lane ([`crate::LinkRate`]).
pub const MAX_LINK_RATE: u32 = 0x00001;
/// MAX_LANE_COUNT: bits 4:0 the lanes; bit 5 POST_LT_ADJ_REQ_SUPPORTED,
/// bit 6 TPS3_SUPPORTED, bit 7 ENHANCED_FRAME_CAP.
pub const MAX_LANE_COUNT: u32 = 0x00002;
pub const TPS3_SUPPORTED: u8 = 1 << 6;
pub const ENHANCED_FRAME_CAP: u8 = 1 << 7;
/// MAX_DOWNSPREAD: bit 0 up to 0.5% down-spread; bit 7 TPS4_SUPPORTED.
pub const MAX_DOWNSPREAD: u32 = 0x00003;
pub const TPS4_SUPPORTED: u8 = 1 << 7;
/// TRAINING_AUX_RD_INTERVAL: bits 6:0 the channel equalization wait (0:
/// 400 µs, n: n × 4 ms; clock recovery always waits 100 µs from DPCD
/// 1.4); bit 7 EXTENDED_RECEIVER_CAPABILITY_FIELD_PRESENT.
pub const TRAINING_AUX_RD_INTERVAL: u32 = 0x0000E;
pub const EXTENDED_CAPS_PRESENT: u8 = 1 << 7;

/// LINK_BW_SET: the link rate chosen, as MAX_LINK_RATE counts it.
pub const LINK_BW_SET: u32 = 0x00100;
/// LANE_COUNT_SET: bits 4:0 the lanes; bit 7 ENHANCED_FRAME_EN.
pub const LANE_COUNT_SET: u32 = 0x00101;
/// TRAINING_PATTERN_SET: bits 3:0 the pattern (0 none, 1 to 3 TPS1 to
/// TPS3, 7 TPS4); bit 5 SCRAMBLING_DISABLE.
pub const TRAINING_PATTERN_SET: u32 = 0x00102;
pub const SCRAMBLING_DISABLE: u8 = 1 << 5;
/// TRAINING_LANE0_SET to TRAINING_LANE3_SET: bits 1:0 the voltage swing
/// level, bit 2 MAX_SWING_REACHED, bits 4:3 the pre-emphasis level, bit 5
/// MAX_PRE-EMPHASIS_REACHED.
pub const TRAINING_LANE0_SET: u32 = 0x00103;
pub const MAX_SWING_REACHED: u8 = 1 << 2;
pub const MAX_PRE_EMPHASIS_REACHED: u8 = 1 << 5;
/// MAIN_LINK_CHANNEL_CODING_SET: 1 for 8b/10b.
pub const MAIN_LINK_CHANNEL_CODING_SET: u32 = 0x00108;

/// SINK_COUNT: bits 5:0 and 7.
pub const SINK_COUNT: u32 = 0x00200;
/// LANE0_1_STATUS and LANE2_3_STATUS: a nibble per lane, bit 0
/// LANE_CR_DONE, bit 1 LANE_CHANNEL_EQ_DONE, bit 2 LANE_SYMBOL_LOCKED.
pub const LANE0_1_STATUS: u32 = 0x00202;
pub const CR_DONE: u8 = 1 << 0;
pub const CHANNEL_EQ_DONE: u8 = 1 << 1;
pub const SYMBOL_LOCKED: u8 = 1 << 2;
/// LANE_ALIGN_STATUS_UPDATED: bit 0 INTERLANE_ALIGN_DONE, bit 7
/// LINK_STATUS_UPDATED.
pub const LANE_ALIGN_STATUS_UPDATED: u32 = 0x00204;
pub const INTERLANE_ALIGN_DONE: u8 = 1 << 0;
/// ADJUST_REQUEST_LANE0_1 and _LANE2_3: a nibble per lane, bits 1:0 the
/// voltage swing asked for, bits 3:2 the pre-emphasis.
pub const ADJUST_REQUEST_LANE0_1: u32 = 0x00206;

/// SET_POWER: 1 for D0 (on), 2 for D3 (off), 5 for D3 with AUX kept on.
pub const SET_POWER: u32 = 0x00600;
pub const POWER_D0: u8 = 1;
pub const POWER_D3: u8 = 2;

/// The Extended Receiver Capability field: the first 16 bytes again, with
/// the true DPCD revision and link rates of DP 1.3 and later (where the
/// field at 00000h stays at what older sources understand).
pub const EXTENDED_CAPS: u32 = 0x02200;
