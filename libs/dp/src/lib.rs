// SPDX-License-Identifier: MIT OR Apache-2.0

//! DisplayPort for Slate's display drivers (ADR 0157, M32 phase 1): the
//! parts every card's DisplayPort output shares, kept apart from any one
//! card so they are tested on the host.
//!
//! - [`Aux`]: the AUX channel's transactions (DP 1.4a §2.7: native reads
//!   and writes of the [`dpcd`], I2C-over-AUX for the display's EDID),
//!   with the DEFER retries the standard asks for;
//! - [`Caps`], [`Link`] and [`fits`]: what a sink can take, and whether
//!   a mode fits a link (8b/10b coding, down-spread);
//! - [`train`]: link training (DP 1.4a §3.5.1.2: clock recovery, then
//!   channel equalization, then falling back to a lower rate or fewer
//!   lanes), driving a card through [`Phy`];
//! - [`sim`]: a simulated sink to train against, as `libs/hci`'s `sim`
//!   is a simulated Bluetooth controller.
//!
//! Sources: the VESA DisplayPort Standard, version 1.4a (2018), and
//! VESA E-DDC 1.3 for the EDID's addresses (docs/gpu/SOURCES.md).

#![no_std]

#[cfg(test)]
extern crate std;

pub mod dpcd;
pub mod sim;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The sink said NACK.
    Nack,
    /// The sink kept saying DEFER.
    Defer,
    /// No reply (the hardware's timeout), more than the retries allow.
    Timeout,
    /// A reply that makes no sense (too short, an unknown code).
    Protocol,
    /// The card couldn't do what it was asked (its own error).
    Hardware,
    /// Training failed at every rate and lane count.
    Training,
}

/// The AUX channel's one operation: a request out, its reply back.
pub trait Aux {
    /// Send `request` (DP 1.4a §2.7.4: the command and address, the
    /// length, then any data; at most 20 bytes) and put the reply (its
    /// command byte, then any data) in `reply`, giving its length.
    /// `Err(Timeout)` when the sink didn't answer in time.
    fn transfer(&mut self, request: &[u8], reply: &mut [u8; 17]) -> Result<usize, Error>;
}

/// Request commands (DP 1.4a §2.7.4, Table 2-147): bit 3 native, else
/// I2C-over-AUX with bit 2 MOT (middle of transaction).
const NATIVE_WRITE: u8 = 0x8;
const NATIVE_READ: u8 = 0x9;
const I2C_WRITE: u8 = 0x0;
const I2C_READ: u8 = 0x1;
const I2C_MOT: u8 = 0x4;

/// Reply codes (Table 2-148), in the reply's top nibble: bits 5:4 the
/// native reply, bits 7:6 the I2C reply; 0 ACK, 1 NACK, 2 DEFER.
fn reply_code(b: u8, i2c: bool) -> Result<(), Error> {
    let native = (b >> 4) & 3;
    let i2c_code = (b >> 6) & 3;
    match (native, if i2c { i2c_code } else { 0 }) {
        (0, 0) => Ok(()),
        (1, _) | (0, 1) => Err(Error::Nack),
        (2, _) | (0, 2) => Err(Error::Defer),
        _ => Err(Error::Protocol),
    }
}

/// The most bytes a transaction carries.
pub const MAX_BYTES: usize = 16;
/// DEFERs taken before giving up: the standard asks sources to retry at
/// least 7 times; sinks waking up from sleep defer for longer.
const DEFER_TRIES: u32 = 32;
const TIMEOUT_TRIES: u32 = 3;

/// One transaction with its retries: `cmd` at `addr`, `data` written or
/// `read` bytes read into `out`. Gives the bytes read (or written).
fn transaction(
    aux: &mut dyn Aux,
    cmd: u8,
    addr: u32,
    data: &[u8],
    read: usize,
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut req = [0u8; 4 + MAX_BYTES];
    req[0] = (cmd << 4) | ((addr >> 16) & 0xF) as u8;
    req[1] = (addr >> 8) as u8;
    req[2] = addr as u8;
    // An address-only transaction (I2C's start or stop) has no length byte.
    let len = if data.is_empty() && read == 0 {
        3
    } else {
        req[3] = (data.len().max(read) - 1) as u8;
        req[4..4 + data.len()].copy_from_slice(data);
        4 + data.len()
    };
    let i2c = cmd & 0x8 == 0;
    let (mut defers, mut timeouts) = (0, 0);
    loop {
        let mut reply = [0u8; 17];
        match aux.transfer(&req[..len], &mut reply) {
            Err(Error::Timeout) => {
                timeouts += 1;
                if timeouts >= TIMEOUT_TRIES {
                    return Err(Error::Timeout);
                }
            }
            Err(e) => return Err(e),
            Ok(0) => return Err(Error::Protocol),
            Ok(n) => match reply_code(reply[0], i2c) {
                Ok(()) => {
                    let got = (n - 1).min(read).min(out.len());
                    out[..got].copy_from_slice(&reply[1..1 + got]);
                    return Ok(if read > 0 { got } else { data.len() });
                }
                Err(Error::Defer) => {
                    defers += 1;
                    if defers >= DEFER_TRIES {
                        return Err(Error::Defer);
                    }
                }
                Err(e) => return Err(e),
            },
        }
    }
}

/// Read DPCD bytes from `addr` (in transactions of up to 16 bytes; a
/// short reply continues from where it stopped).
pub fn read(aux: &mut dyn Aux, addr: u32, buf: &mut [u8]) -> Result<(), Error> {
    let mut done = 0;
    while done < buf.len() {
        let n = (buf.len() - done).min(MAX_BYTES);
        let got = transaction(aux, NATIVE_READ, addr + done as u32, &[], n, &mut buf[done..])?;
        if got == 0 {
            return Err(Error::Protocol);
        }
        done += got;
    }
    Ok(())
}

pub fn read_byte(aux: &mut dyn Aux, addr: u32) -> Result<u8, Error> {
    let mut b = [0];
    read(aux, addr, &mut b)?;
    Ok(b[0])
}

/// Write DPCD bytes at `addr`.
pub fn write(aux: &mut dyn Aux, addr: u32, data: &[u8]) -> Result<(), Error> {
    for (i, chunk) in data.chunks(MAX_BYTES).enumerate() {
        transaction(aux, NATIVE_WRITE, addr + (i * MAX_BYTES) as u32, chunk, 0, &mut [])?;
    }
    Ok(())
}

/// The display's DDC addresses (VESA E-DDC 1.3 §2.2.5): the EDID at 50h,
/// the segment pointer at 30h (each segment two 128-byte blocks).
const DDC_EDID: u32 = 0x50;
const DDC_SEGMENT: u32 = 0x30;

/// Read the display's EDID over I2C-over-AUX (DP 1.4a §2.7.7): the base
/// block, then as many extensions as it lists and `out` holds. Gives the
/// bytes read.
pub fn read_edid(aux: &mut dyn Aux, out: &mut [u8]) -> Result<usize, Error> {
    let blocks = out.len() / 128;
    if blocks == 0 {
        return Ok(0);
    }
    let mut n = 1;
    let mut b = 0;
    while b < n.min(blocks) {
        let segment = (b / 2) as u8;
        let offset = ((b % 2) * 128) as u8;
        let r = (|| {
            if segment > 0 {
                transaction(aux, I2C_WRITE | I2C_MOT, DDC_SEGMENT, &[segment], 0, &mut [])?;
            }
            transaction(aux, I2C_WRITE | I2C_MOT, DDC_EDID, &[offset], 0, &mut [])?;
            let block = &mut out[b * 128..(b + 1) * 128];
            let mut done = 0;
            while done < 128 {
                let got = transaction(aux, I2C_READ | I2C_MOT, DDC_EDID, &[], MAX_BYTES, &mut block[done..])?;
                if got == 0 {
                    return Err(Error::Protocol);
                }
                done += got;
            }
            Ok(())
        })();
        // The stop condition: an address-only read without MOT, sent
        // whatever happened.
        let _ = transaction(aux, I2C_READ, DDC_EDID, &[], 0, &mut []);
        r?;
        if b == 0 {
            n = 1 + usize::from(out[126]);
        }
        b += 1;
    }
    Ok(n.min(blocks) * 128)
}

/// A link rate as DPCD counts it: units of 0.27 Gbps per lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinkRate(pub u8);

impl LinkRate {
    /// 1.62 Gbps (RBR), 2.7 (HBR), 5.4 (HBR2), 8.1 (HBR3).
    pub const RBR: LinkRate = LinkRate(0x06);
    pub const HBR: LinkRate = LinkRate(0x0A);
    pub const HBR2: LinkRate = LinkRate(0x14);
    pub const HBR3: LinkRate = LinkRate(0x1E);
    const ALL: [LinkRate; 4] = [Self::RBR, Self::HBR, Self::HBR2, Self::HBR3];

    /// Per lane, in Mbps on the wire.
    pub fn mbps(self) -> u32 {
        u32::from(self.0) * 270
    }

    /// The next standard rate down, if any.
    pub fn lower(self) -> Option<LinkRate> {
        Self::ALL.iter().rev().copied().find(|&r| r < self)
    }

    /// The highest standard rate at or below a DPCD MAX_LINK_RATE value.
    pub fn at_most(v: u8) -> Option<LinkRate> {
        Self::ALL.iter().rev().copied().find(|r| r.0 <= v)
    }
}

/// A link: its rate and lane count (1, 2 or 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    pub rate: LinkRate,
    pub lanes: u8,
}

impl Link {
    /// What the link carries for pixels, in kbit/s: 8b/10b coding keeps
    /// 8 bits in 10, and down-spread takes up to 0.5% off the clock.
    pub fn payload_kbps(self) -> u64 {
        u64::from(self.lanes) * u64::from(self.rate.mbps()) * 800 * 995 / 1000
    }
}

/// Whether a mode of `clock_khz` at `bpp` bits per pixel fits `link`.
pub fn fits(link: Link, clock_khz: u32, bpp: u32) -> bool {
    u64::from(clock_khz) * u64::from(bpp) <= link.payload_kbps()
}

/// The cheapest link a sink and source both reach that carries the mode:
/// the least bandwidth, then the fewest lanes. None if even the fastest
/// doesn't (a mode for DSC, which Slate doesn't do yet).
pub fn cheapest(max: Link, clock_khz: u32, bpp: u32) -> Option<Link> {
    let mut best: Option<Link> = None;
    for rate in LinkRate::ALL.iter().copied().filter(|&r| r <= max.rate) {
        for lanes in [1, 2, 4].into_iter().filter(|&l| l <= max.lanes) {
            let l = Link { rate, lanes };
            let better = best.is_none_or(|b| (l.payload_kbps(), l.lanes) < (b.payload_kbps(), b.lanes));
            if fits(l, clock_khz, bpp) && better {
                best = Some(l);
            }
        }
    }
    best
}

/// What a sink says it can do (its Receiver Capability field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    /// DPCD_REV (from the extended field when there is one).
    pub rev: u8,
    pub max: Link,
    pub enhanced_framing: bool,
    pub tps3: bool,
    pub tps4: bool,
    /// How long to wait in clock recovery and in channel equalization.
    pub cr_wait_us: u32,
    pub eq_wait_us: u32,
}

/// Read a sink's capabilities. DP 1.3 and later sinks keep their real
/// revision and rates in the extended field at 02200h.
pub fn caps(aux: &mut dyn Aux) -> Result<Caps, Error> {
    let mut c = [0u8; 16];
    read(aux, dpcd::DPCD_REV, &mut c)?;
    let interval = c[0x0E];
    if interval & dpcd::EXTENDED_CAPS_PRESENT != 0 {
        let mut x = [0u8; 16];
        read(aux, dpcd::EXTENDED_CAPS, &mut x)?;
        // Keep the base field's interval: the extended one's means the same.
        c[..0x0E].copy_from_slice(&x[..0x0E]);
    }
    let rate = LinkRate::at_most(c[1]).ok_or(Error::Protocol)?;
    let lanes = match c[2] & 0x1F {
        n if n >= 4 => 4,
        n if n >= 2 => 2,
        1 => 1,
        _ => return Err(Error::Protocol),
    };
    let wait = u32::from(interval & 0x7F);
    let eq_wait_us = if wait == 0 { 400 } else { wait * 4000 };
    // DPCD 1.4 waits 100 µs in clock recovery; older sinks the same as
    // in equalization.
    let cr_wait_us = if c[0] >= 0x14 || wait == 0 { 100 } else { eq_wait_us };
    Ok(Caps {
        rev: c[0],
        max: Link { rate, lanes },
        enhanced_framing: c[2] & dpcd::ENHANCED_FRAME_CAP != 0,
        tps3: c[2] & dpcd::TPS3_SUPPORTED != 0,
        tps4: c[3] & dpcd::TPS4_SUPPORTED != 0,
        cr_wait_us,
        eq_wait_us,
    })
}

/// Training patterns (DP 1.4a §3.5.1.2): TPS1 for clock recovery, TPS2 to
/// TPS4 for channel equalization (TPS4 is scrambled).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pattern {
    None,
    Tps1,
    Tps2,
    Tps3,
    Tps4,
}

impl Pattern {
    /// TRAINING_PATTERN_SET's value for it.
    fn dpcd(self) -> u8 {
        match self {
            Pattern::None => 0,
            Pattern::Tps1 => 1 | dpcd::SCRAMBLING_DISABLE,
            Pattern::Tps2 => 2 | dpcd::SCRAMBLING_DISABLE,
            Pattern::Tps3 => 3 | dpcd::SCRAMBLING_DISABLE,
            Pattern::Tps4 => 7,
        }
    }
}

/// One lane's drive: voltage swing and pre-emphasis levels, 0 to 3, at
/// most 3 together (DP 1.4a §3.1.5's table of allowed pairs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Drive {
    pub swing: u8,
    pub pre_emphasis: u8,
}

impl Drive {
    fn clamped(self) -> Drive {
        let swing = self.swing.min(3);
        Drive { swing, pre_emphasis: self.pre_emphasis.min(3 - swing) }
    }

    /// TRAINING_LANEx_SET's value, with the "maximum reached" flags.
    fn dpcd(self) -> u8 {
        let mut v = self.swing | (self.pre_emphasis << 3);
        if self.swing == 3 {
            v |= dpcd::MAX_SWING_REACHED;
        }
        if self.swing + self.pre_emphasis == 3 {
            v |= dpcd::MAX_PRE_EMPHASIS_REACHED;
        }
        v
    }
}

/// The card's side of a DisplayPort output, which training drives.
pub trait Phy {
    /// Set the link's rate and lanes (the PLL, the lanes powered).
    fn set_link(&mut self, link: Link) -> Result<(), Error>;
    /// Send a training pattern, or none (idle, then video).
    fn set_pattern(&mut self, p: Pattern) -> Result<(), Error>;
    /// Each lane's drive levels.
    fn set_drive(&mut self, lanes: &[Drive; 4]) -> Result<(), Error>;
    fn delay_us(&mut self, us: u32);
}

/// A trained link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trained {
    pub link: Link,
    pub drive: [Drive; 4],
    /// Links tried before this one worked.
    pub fallbacks: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failed {
    ClockRecovery,
    Equalization,
}

/// The lane status registers: LANE0_1_STATUS to ADJUST_REQUEST_LANE2_3.
struct Status([u8; 6]);

impl Status {
    fn lane(&self, i: usize) -> u8 {
        (self.0[i / 2] >> (4 * (i % 2))) & 0xF
    }
    fn all(&self, lanes: u8, bits: u8) -> bool {
        (0..usize::from(lanes)).all(|i| self.lane(i) & bits == bits)
    }
    fn aligned(&self) -> bool {
        self.0[2] & dpcd::INTERLANE_ALIGN_DONE != 0
    }
    /// The drive the sink asks for on each lane.
    fn requested(&self) -> [Drive; 4] {
        let mut d = [Drive::default(); 4];
        for (i, l) in d.iter_mut().enumerate() {
            let v = (self.0[4 + i / 2] >> (4 * (i % 2))) & 0xF;
            *l = Drive { swing: v & 3, pre_emphasis: (v >> 2) & 3 }.clamped();
        }
        d
    }
}

fn status(aux: &mut dyn Aux) -> Result<Status, Error> {
    let mut s = [0u8; 6];
    read(aux, dpcd::LANE0_1_STATUS, &mut s)?;
    Ok(Status(s))
}

/// The lanes' drive to the sink and to the card: TRAINING_LANEx_SET
/// (after TRAINING_PATTERN_SET when `pattern` is given, in one write).
fn send_drive<T: Aux + Phy>(t: &mut T, lanes: u8, drive: &[Drive; 4], pattern: Option<Pattern>) -> Result<(), Error> {
    t.set_drive(drive)?;
    let mut b = [0u8; 5];
    let n = usize::from(lanes);
    for i in 0..n {
        b[1 + i] = drive[i].dpcd();
    }
    match pattern {
        Some(p) => {
            b[0] = p.dpcd();
            write(t, dpcd::TRAINING_PATTERN_SET, &b[..1 + n])
        }
        None => write(t, dpcd::TRAINING_LANE0_SET, &b[1..1 + n]),
    }
}

/// Clock recovery's limits (DP 1.4a §3.5.1.2.2): at most 10 rounds, and
/// give up when the sink asks five times for the same swing.
const CR_ROUNDS: u32 = 10;
const CR_SAME_SWING: u32 = 5;
/// Channel equalization's rounds (§3.5.1.2.3).
const EQ_ROUNDS: u32 = 5;

/// Train one link: clock recovery, then channel equalization. The
/// pattern is off again afterwards whatever happened.
fn try_link<T: Aux + Phy>(t: &mut T, caps: &Caps, link: Link) -> Result<Result<[Drive; 4], Failed>, Error> {
    t.set_pattern(Pattern::None)?;
    t.set_link(link)?;
    let enhanced = if caps.enhanced_framing { 0x80 } else { 0 };
    write(t, dpcd::LINK_BW_SET, &[link.rate.0, link.lanes | enhanced])?;
    write(t, dpcd::MAIN_LINK_CHANNEL_CODING_SET, &[1])?;
    let r = (|| {
        let mut drive = [Drive::default(); 4];
        t.set_pattern(Pattern::Tps1)?;
        send_drive(t, link.lanes, &drive, Some(Pattern::Tps1))?;
        let (mut rounds, mut same) = (0, 0);
        loop {
            t.delay_us(caps.cr_wait_us);
            let s = status(t)?;
            if s.all(link.lanes, dpcd::CR_DONE) {
                break;
            }
            rounds += 1;
            let want = s.requested();
            let lanes = &drive[..usize::from(link.lanes)];
            if rounds >= CR_ROUNDS || lanes.iter().all(|d| d.swing == 3) {
                return Ok(Err(Failed::ClockRecovery));
            }
            let n = usize::from(link.lanes);
            if want[..n].iter().zip(&drive[..n]).all(|(w, d)| w.swing == d.swing) {
                same += 1;
                if same >= CR_SAME_SWING {
                    return Ok(Err(Failed::ClockRecovery));
                }
            } else {
                same = 0;
            }
            drive = want;
            send_drive(t, link.lanes, &drive, None)?;
        }
        let eq = if caps.tps4 {
            Pattern::Tps4
        } else if caps.tps3 {
            Pattern::Tps3
        } else {
            Pattern::Tps2
        };
        t.set_pattern(eq)?;
        send_drive(t, link.lanes, &drive, Some(eq))?;
        for round in 0..=EQ_ROUNDS {
            t.delay_us(caps.eq_wait_us);
            let s = status(t)?;
            if !s.all(link.lanes, dpcd::CR_DONE) {
                return Ok(Err(Failed::Equalization));
            }
            if s.all(link.lanes, dpcd::CHANNEL_EQ_DONE | dpcd::SYMBOL_LOCKED) && s.aligned() {
                return Ok(Ok(drive));
            }
            if round == EQ_ROUNDS {
                break;
            }
            drive = s.requested();
            send_drive(t, link.lanes, &drive, None)?;
        }
        Ok(Err(Failed::Equalization))
    })();
    t.set_pattern(Pattern::None)?;
    write(t, dpcd::TRAINING_PATTERN_SET, &[0])?;
    r
}

/// Train a link, starting at `start` and falling back (DP 1.4a
/// §3.5.1.2.2): a lower rate on the same lanes, and from the lowest rate
/// half the lanes at the starting rate again.
pub fn train<T: Aux + Phy>(t: &mut T, caps: &Caps, start: Link) -> Result<Trained, Error> {
    let mut link = start;
    let mut fallbacks = 0;
    loop {
        if let Ok(drive) = try_link(t, caps, link)? {
            return Ok(Trained { link, drive, fallbacks });
        }
        fallbacks += 1;
        link = match link.rate.lower() {
            Some(rate) => Link { rate, lanes: link.lanes },
            None if link.lanes > 1 => Link { rate: start.rate, lanes: link.lanes / 2 },
            None => return Err(Error::Training),
        };
    }
}

/// Wake the sink (SET_POWER to D0). Sinks may take up to 1 ms to answer
/// after waking, so the first writes are retried.
pub fn wake(aux: &mut dyn Aux) -> Result<(), Error> {
    let mut last = Error::Timeout;
    for _ in 0..3 {
        match write(aux, dpcd::SET_POWER, &[dpcd::POWER_D0]) {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
    }
    Err(last)
}
