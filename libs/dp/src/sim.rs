// SPDX-License-Identifier: MIT OR Apache-2.0

//! A simulated DisplayPort sink and the cable to it (ADR 0157): a
//! [`Bench`] is both a card's output ([`Phy`]) and its AUX channel
//! ([`Aux`]), wired to a [`Sink`] whose behaviour the tests choose: its
//! capabilities, the drive levels its lanes need, rates or lanes that
//! never lock, DEFERs, an EDID behind I2C-over-AUX. The sink reports
//! lock only when what the source wrote to its DPCD agrees with what the
//! source's PHY actually sends, so a driver that forgets one of the two
//! fails here as it would on a cable.

use crate::{Aux, Drive, Error, Link, LinkRate, Pattern, Phy, dpcd};

/// What the sink is and does.
#[derive(Clone, Copy, Debug)]
pub struct Sink {
    /// Plugged in: without it every transaction times out.
    pub present: bool,
    /// The DPCD revision (14h for 1.4).
    pub rev: u8,
    pub max: Link,
    /// DP 1.3 and later: the true revision and rates only in the
    /// extended field, the base field saying 1.2 and HBR2.
    pub extended: bool,
    pub enhanced_framing: bool,
    pub tps3: bool,
    pub tps4: bool,
    /// TRAINING_AUX_RD_INTERVAL's bits 6:0.
    pub interval: u8,
    /// Above this rate clock recovery never locks (a poor cable).
    pub good_rate: LinkRate,
    /// Lanes from this one up never lock (a broken lane).
    pub good_lanes: u8,
    /// The voltage swing clock recovery needs; the pre-emphasis
    /// equalization needs.
    pub cr_swing: u8,
    pub eq_pre: u8,
    /// Asks for the drive it already has, whatever the result.
    pub stubborn: bool,
    /// Every request is answered DEFER this many times first.
    pub defers: u8,
    pub edid: [u8; 512],
    pub edid_len: usize,
}

impl Sink {
    /// A healthy DP 1.4 monitor: HBR3 on four lanes, TPS3 and TPS4, that
    /// wants a swing of 1 and a pre-emphasis of 1.
    pub fn monitor() -> Sink {
        Sink {
            present: true,
            rev: 0x14,
            max: Link { rate: LinkRate::HBR3, lanes: 4 },
            extended: true,
            enhanced_framing: true,
            tps3: true,
            tps4: true,
            interval: 0,
            good_rate: LinkRate::HBR3,
            good_lanes: 4,
            cr_swing: 1,
            eq_pre: 1,
            stubborn: false,
            defers: 0,
            edid: [0; 512],
            edid_len: 0,
        }
    }

    pub fn with_edid(mut self, e: &[u8]) -> Sink {
        let n = e.len().min(self.edid.len());
        self.edid[..n].copy_from_slice(&e[..n]);
        self.edid_len = n;
        self
    }
}

/// The sink on the end of a source's output.
#[derive(Clone, Copy, Debug)]
pub struct Bench {
    pub sink: Sink,
    /// The sink's link configuration (00100h to 0010Fh) and SET_POWER.
    config: [u8; 16],
    pub power: u8,
    /// What the source's PHY is doing.
    pub phy_link: Option<Link>,
    pub phy_pattern: Pattern,
    pub phy_drive: [Drive; 4],
    /// Time the source spent waiting, and the trainings it began.
    pub waited_us: u64,
    pub trainings: u32,
    pub transactions: u32,
    deferred: u8,
    segment: u8,
    offset: u8,
}

impl Bench {
    pub fn new(sink: Sink) -> Bench {
        Bench {
            sink,
            config: [0; 16],
            power: dpcd::POWER_D3,
            phy_link: None,
            phy_pattern: Pattern::None,
            phy_drive: [Drive::default(); 4],
            waited_us: 0,
            trainings: 0,
            transactions: 0,
            deferred: 0,
            segment: 0,
            offset: 0,
        }
    }

    /// The link the sink was told to expect.
    pub fn sink_link(&self) -> Link {
        Link { rate: LinkRate(self.config[0]), lanes: self.config[1] & 0x1F }
    }

    fn sink_drive(&self, i: usize) -> Drive {
        let v = self.config[3 + i];
        Drive { swing: v & 3, pre_emphasis: (v >> 3) & 3 }
    }

    fn sink_pattern(&self) -> Pattern {
        match self.config[2] & 0xF {
            1 => Pattern::Tps1,
            2 => Pattern::Tps2,
            3 => Pattern::Tps3,
            7 => Pattern::Tps4,
            _ => Pattern::None,
        }
    }

    /// Whether lane `i` carries a signal the sink can use.
    fn signal(&self, i: usize) -> bool {
        let s = &self.sink;
        let l = self.sink_link();
        self.power == dpcd::POWER_D0
            && self.phy_link == Some(l)
            && l.rate <= s.good_rate
            && l.rate <= s.max.rate
            && i < usize::from(l.lanes.min(s.good_lanes))
            && self.phy_drive[i] == self.sink_drive(i)
            && self.phy_pattern != Pattern::None
            && self.phy_pattern == self.sink_pattern()
    }

    fn cr(&self, i: usize) -> bool {
        self.signal(i) && self.phy_drive[i].swing >= self.sink.cr_swing
    }

    fn eq(&self, i: usize) -> bool {
        self.cr(i) && self.phy_pattern != Pattern::Tps1 && self.phy_drive[i].pre_emphasis >= self.sink.eq_pre
    }

    /// The lane status registers, 00202h to 00207h.
    fn status(&self) -> [u8; 6] {
        let lanes = usize::from(self.sink_link().lanes.min(4));
        let mut s = [0u8; 6];
        for i in 0..lanes {
            let mut v = 0;
            if self.cr(i) {
                v |= dpcd::CR_DONE;
            }
            if self.eq(i) {
                v |= dpcd::CHANNEL_EQ_DONE | dpcd::SYMBOL_LOCKED;
            }
            s[i / 2] |= v << (4 * (i % 2));
            // What it asks for: enough swing, then enough pre-emphasis
            // while equalizing, at most 3 together.
            let cur = self.sink_drive(i);
            let want = if self.sink.stubborn {
                cur
            } else {
                let swing = cur.swing.max(self.sink.cr_swing).min(3);
                let pre = if self.phy_pattern == Pattern::Tps1 {
                    cur.pre_emphasis
                } else {
                    cur.pre_emphasis.max(self.sink.eq_pre)
                };
                Drive { swing, pre_emphasis: pre.min(3 - swing) }
            };
            s[4 + i / 2] |= (want.swing | (want.pre_emphasis << 2)) << (4 * (i % 2));
        }
        if lanes > 0 && (0..lanes).all(|i| self.eq(i)) {
            s[2] |= dpcd::INTERLANE_ALIGN_DONE;
        }
        s
    }

    fn read_dpcd(&self, addr: u32) -> u8 {
        let s = &self.sink;
        let lanes = |m: Link| {
            m.lanes
                | if s.tps3 { dpcd::TPS3_SUPPORTED } else { 0 }
                | if s.enhanced_framing { dpcd::ENHANCED_FRAME_CAP } else { 0 }
        };
        let tps4 = if s.tps4 { dpcd::TPS4_SUPPORTED } else { 0 };
        // The base field of an extended sink says DPCD 1.2 and at most HBR2.
        let base_rate = if s.extended { s.max.rate.min(LinkRate::HBR2) } else { s.max.rate };
        match addr {
            0x00000 => {
                if s.extended {
                    0x12
                } else {
                    s.rev
                }
            }
            0x00001 => base_rate.0,
            0x00002 => lanes(s.max),
            0x00003 => 0x01 | tps4,
            0x0000E => s.interval | if s.extended { dpcd::EXTENDED_CAPS_PRESENT } else { 0 },
            0x00100..=0x0010F => self.config[(addr - 0x100) as usize],
            0x00200 => 1,
            0x00202..=0x00207 => self.status()[(addr - 0x202) as usize],
            0x00600 => self.power,
            0x02200 if s.extended => s.rev,
            0x02201 if s.extended => s.max.rate.0,
            0x02202 if s.extended => lanes(s.max),
            0x02203 if s.extended => 0x01 | tps4,
            0x0220E if s.extended => s.interval,
            _ => 0,
        }
    }

    fn write_dpcd(&mut self, addr: u32, v: u8) {
        match addr {
            0x00100..=0x0010F => {
                if addr == dpcd::LINK_BW_SET {
                    self.trainings += 1;
                }
                self.config[(addr - 0x100) as usize] = v;
            }
            0x00600 => self.power = v,
            _ => {}
        }
    }
}

const NATIVE_ACK: u8 = 0x00;
const NATIVE_DEFER: u8 = 0x20;
const I2C_NACK: u8 = 0x40;
const I2C_DEFER: u8 = 0x80;

impl Aux for Bench {
    fn transfer(&mut self, req: &[u8], reply: &mut [u8; 17]) -> Result<usize, Error> {
        if !self.sink.present {
            return Err(Error::Timeout);
        }
        if req.len() < 3 {
            return Err(Error::Protocol);
        }
        self.transactions += 1;
        let cmd = req[0] >> 4;
        let native = cmd & 0x8 != 0;
        if self.deferred < self.sink.defers {
            self.deferred += 1;
            reply[0] = if native { NATIVE_DEFER } else { I2C_DEFER };
            return Ok(1);
        }
        self.deferred = 0;
        let addr = (u32::from(req[0] & 0xF) << 16) | (u32::from(req[1]) << 8) | u32::from(req[2]);
        let len = req.get(3).map_or(0, |&l| usize::from(l) + 1);
        reply[0] = NATIVE_ACK;
        if native {
            if cmd == 0x9 {
                for i in 0..len.min(16) {
                    reply[1 + i] = self.read_dpcd(addr + i as u32);
                }
                return Ok(1 + len.min(16));
            }
            for (i, &v) in req[4..].iter().enumerate() {
                self.write_dpcd(addr + i as u32, v);
            }
            return Ok(1);
        }
        let mot = cmd & 0x4 != 0;
        let r = match (cmd & 3, addr) {
            // An address-only transaction: a start, or without MOT a stop
            // (which E-DDC says resets the segment pointer).
            (_, _) if len == 0 => {
                if !mot {
                    self.segment = 0;
                }
                Ok(1)
            }
            (0, 0x30) => {
                self.segment = req[4];
                Ok(1)
            }
            (0, 0x50) => {
                self.offset = req[4];
                Ok(1)
            }
            (1, 0x50) => {
                for i in 0..len.min(16) {
                    let at = usize::from(self.segment) * 256 + usize::from(self.offset);
                    reply[1 + i] = if at < self.sink.edid_len { self.sink.edid[at] } else { 0xFF };
                    self.offset = self.offset.wrapping_add(1);
                }
                Ok(1 + len.min(16))
            }
            _ => {
                reply[0] = I2C_NACK;
                Ok(1)
            }
        };
        if !mot && len > 0 {
            self.segment = 0;
        }
        r
    }
}

impl Phy for Bench {
    fn set_link(&mut self, link: Link) -> Result<(), Error> {
        self.phy_link = Some(link);
        Ok(())
    }
    fn set_pattern(&mut self, p: Pattern) -> Result<(), Error> {
        self.phy_pattern = p;
        Ok(())
    }
    fn set_drive(&mut self, lanes: &[Drive; 4]) -> Result<(), Error> {
        self.phy_drive = *lanes;
        Ok(())
    }
    fn delay_us(&mut self, us: u32) {
        self.waited_us += u64::from(us);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Trained, caps, cheapest, fits, read, read_edid, train, wake};

    fn trained(sink: Sink) -> (Result<Trained, Error>, Bench) {
        let mut b = Bench::new(sink);
        wake(&mut b).unwrap();
        let c = caps(&mut b).unwrap();
        let r = train(&mut b, &c, c.max);
        (r, b)
    }

    #[test]
    fn a_healthy_monitor_trains_at_its_best() {
        let mut b = Bench::new(Sink::monitor());
        wake(&mut b).unwrap();
        let c = caps(&mut b).unwrap();
        // The extended field's revision and rate, not the base field's.
        assert_eq!((c.rev, c.max), (0x14, Link { rate: LinkRate::HBR3, lanes: 4 }));
        assert!(c.tps3 && c.tps4 && c.enhanced_framing);
        assert_eq!((c.cr_wait_us, c.eq_wait_us), (100, 400));
        let t = train(&mut b, &c, c.max).unwrap();
        assert_eq!(t.link, c.max);
        assert_eq!(t.fallbacks, 0);
        assert_eq!(t.drive, [Drive { swing: 1, pre_emphasis: 1 }; 4]);
        // The pattern is off afterwards, on both sides.
        assert_eq!((b.phy_pattern, b.read_dpcd(dpcd::TRAINING_PATTERN_SET)), (Pattern::None, 0));
        assert_eq!(b.read_dpcd(dpcd::LANE_COUNT_SET), 0x84);
        assert_eq!(b.trainings, 1);
        // One round of clock recovery asked for swing 1, then one of
        // equalization for pre-emphasis 1.
        assert_eq!(b.waited_us, 100 * 2 + 400 * 2);
    }

    #[test]
    fn falls_back_to_a_rate_the_cable_carries() {
        let (t, b) = trained(Sink { good_rate: LinkRate::HBR2, ..Sink::monitor() });
        let t = t.unwrap();
        assert_eq!(t.link, Link { rate: LinkRate::HBR2, lanes: 4 });
        assert_eq!((t.fallbacks, b.trainings), (1, 2));
    }

    #[test]
    fn a_broken_lane_halves_the_link() {
        // Lanes 2 and 3 never lock: every rate on four lanes fails, then
        // two lanes at HBR3 work.
        let (t, _) = trained(Sink { good_lanes: 2, ..Sink::monitor() });
        let t = t.unwrap();
        assert_eq!(t.link, Link { rate: LinkRate::HBR3, lanes: 2 });
        assert_eq!(t.fallbacks, 4);
    }

    #[test]
    fn gives_up_when_nothing_locks() {
        // Asking for the same swing five times ends clock recovery.
        let (t, b) = trained(Sink { stubborn: true, ..Sink::monitor() });
        assert_eq!(t, Err(Error::Training));
        // 4 rates × 3 lane counts.
        assert_eq!(b.trainings, 12);
        // Drive levels that can't be had together: clock recovery works,
        // equalization never does.
        let (t, _) = trained(Sink { cr_swing: 2, eq_pre: 2, ..Sink::monitor() });
        assert_eq!(t, Err(Error::Training));
    }

    #[test]
    fn older_sinks_and_their_waits() {
        // DPCD 1.2: no extended field, HBR2, TPS3 but not TPS4, 8 ms waits
        // in both phases.
        let sink = Sink {
            rev: 0x12,
            extended: false,
            tps4: false,
            interval: 2,
            max: Link { rate: LinkRate::HBR2, lanes: 2 },
            good_rate: LinkRate::HBR2,
            ..Sink::monitor()
        };
        let mut b = Bench::new(sink);
        wake(&mut b).unwrap();
        let c = caps(&mut b).unwrap();
        assert_eq!((c.rev, c.max.rate, c.max.lanes, c.tps4), (0x12, LinkRate::HBR2, 2, false));
        assert_eq!((c.cr_wait_us, c.eq_wait_us), (8000, 8000));
        assert_eq!(train(&mut b, &c, c.max).unwrap().link, c.max);
        assert_eq!(b.waited_us, 8000 * 4);
    }

    #[test]
    fn the_source_must_drive_what_it_wrote() {
        // A PHY that doesn't follow the drive levels it wrote to the sink
        // never locks (here: drive levels never reach the PHY).
        struct Deaf(Bench);
        impl Aux for Deaf {
            fn transfer(&mut self, r: &[u8], o: &mut [u8; 17]) -> Result<usize, Error> {
                self.0.transfer(r, o)
            }
        }
        impl Phy for Deaf {
            fn set_link(&mut self, l: Link) -> Result<(), Error> {
                self.0.set_link(l)
            }
            fn set_pattern(&mut self, p: Pattern) -> Result<(), Error> {
                self.0.set_pattern(p)
            }
            fn set_drive(&mut self, _: &[Drive; 4]) -> Result<(), Error> {
                Ok(())
            }
            fn delay_us(&mut self, us: u32) {
                self.0.delay_us(us)
            }
        }
        let mut d = Deaf(Bench::new(Sink::monitor()));
        wake(&mut d).unwrap();
        let c = caps(&mut d).unwrap();
        assert_eq!(train(&mut d, &c, c.max), Err(Error::Training));
    }

    #[test]
    fn defers_are_retried_and_absent_sinks_time_out() {
        let mut b = Bench::new(Sink { defers: 3, ..Sink::monitor() });
        let mut buf = [0u8; 16];
        read(&mut b, 0, &mut buf).unwrap();
        assert_eq!(buf[0], 0x12);
        assert_eq!(b.transactions, 4);
        let mut b = Bench::new(Sink { defers: 200, ..Sink::monitor() });
        assert_eq!(read(&mut b, 0, &mut buf), Err(Error::Defer));
        let mut b = Bench::new(Sink { present: false, ..Sink::monitor() });
        assert_eq!(read(&mut b, 0, &mut buf), Err(Error::Timeout));
        assert_eq!(wake(&mut b), Err(Error::Timeout));
    }

    #[test]
    fn edid_over_i2c_over_aux() {
        // Four blocks: the second pair behind the segment pointer.
        let mut e = [0u8; 512];
        let base = slate_edid::build(&slate_edid::Display {
            vendor: *b"SLT",
            product: 1,
            serial: 1,
            year: 2026,
            name: "dp sim",
            size_mm: (600, 340),
            timing: slate_edid::timings::cvt(3840, 2160, 60, slate_edid::timings::Blanking::Reduced).unwrap(),
        });
        e[..128].copy_from_slice(&base);
        e[126] = 3;
        e[127] = e[127].wrapping_sub(3);
        for (i, b) in e[128..].chunks_mut(128).enumerate() {
            b.fill(0x10 + i as u8);
        }
        let mut b = Bench::new(Sink { defers: 1, ..Sink::monitor() }.with_edid(&e));
        let mut out = [0u8; 512];
        assert_eq!(read_edid(&mut b, &mut out), Ok(512));
        assert_eq!(out, e);
        assert!(slate_edid::parse(&out).is_some());
        // Room for the base block only.
        let mut small = [0u8; 200];
        assert_eq!(read_edid(&mut b, &mut small), Ok(128));
        // Nothing at another address: the sink NACKs.
        assert_eq!(crate::transaction(&mut b, 0x1 | 0x4, 0x51, &[], 16, &mut [0; 16]), Err(Error::Nack));
    }

    #[test]
    fn modes_and_links() {
        let hbr = |rate, lanes| Link { rate, lanes };
        // 4K at 60 (CVT-RB, 533.25 MHz) in 24-bit colour: 12.8 Gbps.
        assert!(!fits(hbr(LinkRate::HBR, 4), 533_250, 24));
        assert!(fits(hbr(LinkRate::HBR2, 4), 533_250, 24));
        assert!(fits(hbr(LinkRate::HBR3, 2), 533_250, 24));
        assert_eq!(cheapest(hbr(LinkRate::HBR3, 4), 533_250, 24), Some(hbr(LinkRate::HBR3, 2)));
        // The reference PC's monitor at 1080p 144 Hz: 325.08 MHz.
        assert_eq!(cheapest(hbr(LinkRate::HBR3, 4), 325_080, 24), Some(hbr(LinkRate::HBR2, 2)));
        // 4K at 144 (1.3 GHz) wants DSC.
        assert_eq!(cheapest(hbr(LinkRate::HBR3, 4), 1_306_206, 24), None);
        assert_eq!(LinkRate::HBR3.lower(), Some(LinkRate::HBR2));
        assert_eq!(LinkRate::RBR.lower(), None);
        assert_eq!(LinkRate::at_most(0x19), Some(LinkRate::HBR2));
        assert_eq!(LinkRate::HBR2.mbps(), 5400);
    }
}
