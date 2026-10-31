// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hardware parameters: the space a program narrows with `HW_REFINE`
//! until one configuration is left for `HW_PARAMS` (ADR 0184).
//!
//! Three parameters are sets (access, format, subformat: bit masks), the
//! rest ranges of whole or real numbers (intervals with open or closed
//! ends). Slate's refinement is its own: what the hardware allows is
//! applied first, then every relation the parameters' definitions imply
//! narrows the others, both ways, until nothing changes:
//!
//! - sample bits are the formats' widths in memory;
//! - frame bits = sample bits x channels;
//! - period (buffer) bytes = period (buffer) size x frame bits / 8;
//! - buffer size = period size x periods;
//! - period (buffer) time in microseconds = size x 1 000 000 / rate.
//!
//! Interval arithmetic keeps the bounds safe: a bound that falls between
//! two whole numbers is rounded outwards and marked open.

use crate::abi::*;

/// A set of small numbers (formats, access types), as `struct snd_mask`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mask(pub [u32; 8]);

impl Mask {
    pub const NONE: Mask = Mask([0; 8]);
    pub const ALL: Mask = Mask([!0; 8]);

    pub fn of(values: &[u32]) -> Mask {
        let mut m = Mask::NONE;
        for &v in values {
            m.set(v);
        }
        m
    }
    pub fn set(&mut self, v: u32) {
        if v < 256 {
            self.0[(v / 32) as usize] |= 1 << (v % 32);
        }
    }
    pub fn has(&self, v: u32) -> bool {
        v < 256 && self.0[(v / 32) as usize] >> (v % 32) & 1 == 1
    }
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&w| w == 0)
    }
    pub fn values(&self) -> impl Iterator<Item = u32> + '_ {
        (0..256).filter(|&v| self.has(v))
    }
    pub fn first(&self) -> Option<u32> {
        self.values().next()
    }
    pub fn single(&self) -> Option<u32> {
        let mut it = self.values();
        let v = it.next()?;
        if it.next().is_none() { Some(v) } else { None }
    }
    /// Keep only what `other` has too; true if this changed.
    pub fn refine(&mut self, other: &Mask) -> bool {
        let old = *self;
        for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
            *a &= *b;
        }
        *self != old
    }
}

/// A range of numbers, as `struct snd_interval`: `min` to `max`, either
/// end open (excluded), whole numbers only if `integer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval {
    pub min: u32,
    pub max: u32,
    pub openmin: bool,
    pub openmax: bool,
    pub integer: bool,
    pub empty: bool,
}

/// A parameter was narrowed to nothing: no configuration is left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Empty;

impl Interval {
    pub const FULL: Interval =
        Interval { min: 0, max: u32::MAX, openmin: false, openmax: false, integer: false, empty: false };

    pub const fn range(min: u32, max: u32) -> Interval {
        Interval { min, max, openmin: false, openmax: false, integer: false, empty: false }
    }
    pub const fn whole(min: u32, max: u32) -> Interval {
        Interval { min, max, openmin: false, openmax: false, integer: true, empty: false }
    }
    pub const fn value(v: u32) -> Interval {
        Interval::whole(v, v)
    }

    fn check(&mut self) -> Result<(), Empty> {
        if self.integer {
            if self.openmin {
                self.min = self.min.checked_add(1).ok_or(Empty)?;
                self.openmin = false;
            }
            if self.openmax {
                self.max = self.max.checked_sub(1).ok_or(Empty)?;
                self.openmax = false;
            }
        }
        if self.min > self.max || (self.min == self.max && (self.openmin || self.openmax)) {
            self.empty = true;
            return Err(Empty);
        }
        Ok(())
    }

    /// Narrow to what `other` allows too; true if this changed.
    pub fn refine(&mut self, other: &Interval) -> Result<bool, Empty> {
        if self.empty || other.empty {
            self.empty = true;
            return Err(Empty);
        }
        let old = *self;
        if other.min > self.min || (other.min == self.min && other.openmin && !self.openmin) {
            self.min = other.min;
            self.openmin = other.openmin;
        }
        if other.max < self.max || (other.max == self.max && other.openmax && !self.openmax) {
            self.max = other.max;
            self.openmax = other.openmax;
        }
        self.integer |= other.integer;
        self.check()?;
        Ok(*self != old)
    }

    /// Whether only one value is left (a real range shorter than one,
    /// open at an end, counts as its whole number).
    pub fn single(&self) -> Option<u32> {
        if self.empty {
            return None;
        }
        if self.min == self.max {
            return Some(self.min);
        }
        if self.min.checked_add(1) == Some(self.max) && (self.openmin || self.openmax) {
            return Some(if self.openmin && !self.openmax { self.max } else { self.min });
        }
        None
    }

    /// The smallest value it holds.
    pub fn least(&self) -> u32 {
        if self.openmin { self.min.saturating_add(1) } else { self.min }
    }

    /// The largest value it holds.
    pub fn most(&self) -> u32 {
        if self.openmax { self.max.saturating_sub(1) } else { self.max }
    }

    /// Narrow to the multiples of `step` it holds.
    pub fn refine_step(&mut self, step: u32) -> Result<bool, Empty> {
        if step <= 1 {
            return Ok(false);
        }
        let lo = self.least().div_ceil(step).saturating_mul(step);
        let hi = self.most() / step * step;
        let mut r = Interval::whole(lo, hi);
        r.integer = self.integer;
        self.refine(&r)
    }

    /// Narrow to the values of `list` it holds (sorted).
    pub fn refine_list(&mut self, list: &[u32]) -> Result<bool, Empty> {
        let lo = list.iter().copied().find(|&v| v >= self.least()).ok_or(Empty)?;
        let hi = list.iter().copied().rev().find(|&v| v <= self.most()).ok_or(Empty)?;
        if lo > hi {
            self.empty = true;
            return Err(Empty);
        }
        let mut r = Interval::range(lo, hi);
        r.integer = true;
        self.refine(&r)
    }
}

/// floor and ceil of `n / d` with whether it was exact, saturated to u32.
fn div_bounds(n: u64, d: u64) -> (u32, u32, bool) {
    let q = n / d;
    let exact = n % d == 0;
    let lo = q.min(u64::from(u32::MAX)) as u32;
    let hi = (if exact { q } else { q + 1 }).min(u64::from(u32::MAX)) as u32;
    (lo, hi, exact)
}

/// `a x b`.
pub fn mul(a: &Interval, b: &Interval) -> Interval {
    let lo = u64::from(a.min) * u64::from(b.min);
    let hi = u64::from(a.max) * u64::from(b.max);
    Interval {
        min: lo.min(u64::from(u32::MAX)) as u32,
        max: hi.min(u64::from(u32::MAX)) as u32,
        openmin: a.openmin || b.openmin,
        openmax: (a.openmax || b.openmax) && hi <= u64::from(u32::MAX),
        integer: a.integer && b.integer,
        empty: false,
    }
}

/// `a / b`.
pub fn div(a: &Interval, b: &Interval) -> Interval {
    let mut r = Interval::FULL;
    if b.max == 0 {
        return r;
    }
    let (lo, _, exact) = div_bounds(u64::from(a.min), u64::from(b.max));
    r.min = lo;
    r.openmin = !exact || a.openmin || b.openmax;
    if b.min > 0 {
        let (_, hi, exact) = div_bounds(u64::from(a.max), u64::from(b.min));
        r.max = hi;
        r.openmax = !exact || a.openmax || b.openmin;
    }
    r
}

/// `a x b / k`.
pub fn muldivk(a: &Interval, b: &Interval, k: u32) -> Interval {
    let mut r = Interval::FULL;
    let (lo, _, exact) = div_bounds(u64::from(a.min) * u64::from(b.min), u64::from(k));
    r.min = lo;
    r.openmin = !exact || a.openmin || b.openmin;
    let (_, hi, exact) = div_bounds(u64::from(a.max) * u64::from(b.max), u64::from(k));
    r.max = hi;
    r.openmax = (!exact || a.openmax || b.openmax) && hi < u32::MAX;
    r
}

/// `a x k / b`.
pub fn mulkdiv(a: &Interval, k: u32, b: &Interval) -> Interval {
    let mut r = Interval::FULL;
    if b.max == 0 {
        return r;
    }
    let (lo, _, exact) = div_bounds(u64::from(a.min) * u64::from(k), u64::from(b.max));
    r.min = lo;
    r.openmin = !exact || a.openmin || b.openmax;
    if b.min > 0 {
        let (_, hi, exact) = div_bounds(u64::from(a.max) * u64::from(k), u64::from(b.min));
        r.max = hi;
        r.openmax = (!exact || a.openmax || b.openmin) && hi < u32::MAX;
    }
    r
}

/// The parameter space of `struct snd_pcm_hw_params`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HwParams {
    pub flags: u32,
    pub masks: [Mask; 3],
    /// SAMPLE_BITS (8) to TICK_TIME (19).
    pub intervals: [Interval; 12],
    pub rmask: u32,
    pub cmask: u32,
    pub info: u32,
    pub msbits: u32,
    pub rate_num: u32,
    pub rate_den: u32,
    pub fifo_size: u64,
}

impl HwParams {
    /// Everything open.
    pub fn any() -> HwParams {
        HwParams {
            flags: 0,
            masks: [Mask::ALL; 3],
            intervals: [Interval::FULL; 12],
            rmask: !0,
            cmask: 0,
            info: !0,
            msbits: 0,
            rate_num: 0,
            rate_den: 0,
            fifo_size: 0,
        }
    }

    pub fn mask(&self, p: usize) -> &Mask {
        &self.masks[p]
    }
    pub fn mask_mut(&mut self, p: usize) -> &mut Mask {
        &mut self.masks[p]
    }
    pub fn interval(&self, p: usize) -> &Interval {
        &self.intervals[p - HW_PARAM_FIRST_INTERVAL]
    }
    pub fn interval_mut(&mut self, p: usize) -> &mut Interval {
        &mut self.intervals[p - HW_PARAM_FIRST_INTERVAL]
    }

    /// Read the structure (`buf` is its 608 bytes).
    pub fn decode(buf: &[u8]) -> HwParams {
        let mut p = HwParams::any();
        p.flags = get_u32(buf, HWP_FLAGS);
        for (i, m) in p.masks.iter_mut().enumerate() {
            for (w, word) in m.0.iter_mut().enumerate() {
                *word = get_u32(buf, HWP_MASKS + i * HWP_MASK_SIZE + w * 4);
            }
        }
        for (i, iv) in p.intervals.iter_mut().enumerate() {
            let o = HWP_INTERVALS + i * HWP_INTERVAL_SIZE;
            let bits = get_u32(buf, o + 8);
            *iv = Interval {
                min: get_u32(buf, o),
                max: get_u32(buf, o + 4),
                openmin: bits & 1 != 0,
                openmax: bits & 2 != 0,
                integer: bits & 4 != 0,
                empty: bits & 8 != 0,
            };
        }
        p.rmask = get_u32(buf, HWP_RMASK);
        p.cmask = get_u32(buf, HWP_CMASK);
        p.info = get_u32(buf, HWP_INFO);
        p.msbits = get_u32(buf, HWP_MSBITS);
        p.rate_num = get_u32(buf, HWP_RATE_NUM);
        p.rate_den = get_u32(buf, HWP_RATE_DEN);
        p.fifo_size = get_u64(buf, HWP_FIFO_SIZE);
        p
    }

    /// Write it back into `buf` (the reserved parts are left as they are).
    pub fn encode(&self, buf: &mut [u8]) {
        put_u32(buf, HWP_FLAGS, self.flags);
        for (i, m) in self.masks.iter().enumerate() {
            for (w, word) in m.0.iter().enumerate() {
                put_u32(buf, HWP_MASKS + i * HWP_MASK_SIZE + w * 4, *word);
            }
        }
        for (i, iv) in self.intervals.iter().enumerate() {
            let o = HWP_INTERVALS + i * HWP_INTERVAL_SIZE;
            let bits = u32::from(iv.openmin)
                | u32::from(iv.openmax) << 1
                | u32::from(iv.integer) << 2
                | u32::from(iv.empty) << 3;
            put_u32(buf, o, iv.min);
            put_u32(buf, o + 4, iv.max);
            put_u32(buf, o + 8, bits);
        }
        put_u32(buf, HWP_RMASK, self.rmask);
        put_u32(buf, HWP_CMASK, self.cmask);
        put_u32(buf, HWP_INFO, self.info);
        put_u32(buf, HWP_MSBITS, self.msbits);
        put_u32(buf, HWP_RATE_NUM, self.rate_num);
        put_u32(buf, HWP_RATE_DEN, self.rate_den);
        put_u64(buf, HWP_FIFO_SIZE, self.fifo_size);
    }

    /// The value of a parameter that has only one left.
    pub fn get(&self, p: usize) -> Option<u32> {
        if p <= HW_PARAM_SUBFORMAT { self.masks[p].single() } else { self.interval(p).single() }
    }
}

/// What a stream's hardware allows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hardware {
    pub info: u32,
    pub access: Mask,
    pub formats: Mask,
    /// Significant bits of a sample in a 32-bit format (24 for 24-bit
    /// converters behind S32_LE; 0: all of them).
    pub msbits32: u32,
    pub channels: Interval,
    /// Sorted.
    pub rates: alloc_free::Rates,
    pub period_bytes: Interval,
    /// Period sizes in bytes must be multiples of this.
    pub period_align: u32,
    pub periods: Interval,
    pub buffer_bytes_max: u32,
}

/// A short sorted list of rates without an allocator.
pub mod alloc_free {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Rates {
        pub list: [u32; 16],
        pub len: usize,
    }
    impl Rates {
        pub fn of(rates: &[u32]) -> Rates {
            let mut r = Rates { list: [0; 16], len: 0 };
            for &v in rates.iter().take(16) {
                r.list[r.len] = v;
                r.len += 1;
            }
            r.list[..r.len].sort_unstable();
            r
        }
        pub fn as_slice(&self) -> &[u32] {
            &self.list[..self.len]
        }
    }
}

fn changed(cmask: &mut u32, p: usize, r: Result<bool, Empty>) -> Result<(), Empty> {
    if r? {
        *cmask |= 1 << p;
    }
    Ok(())
}

/// Narrow `p` to what `hw` allows and to what the parameters' relations
/// leave, as `HW_REFINE` does. `cmask` says which parameters changed;
/// `info`, `msbits` and the rate's fraction are filled in once known.
pub fn refine(p: &mut HwParams, hw: &Hardware) -> Result<(), Empty> {
    let before = *p;
    // Which parameters a step changed; `cmask` is worked out at the end
    // from what really changed.
    let mut cm = 0u32;
    // What the hardware allows.
    p.masks[HW_PARAM_ACCESS].refine(&hw.access);
    p.masks[HW_PARAM_FORMAT].refine(&hw.formats);
    p.masks[HW_PARAM_SUBFORMAT].refine(&Mask::of(&[SUBFORMAT_STD]));
    for m in [HW_PARAM_ACCESS, HW_PARAM_FORMAT, HW_PARAM_SUBFORMAT] {
        if p.masks[m].is_empty() {
            return Err(Empty);
        }
    }
    // Only known formats, whose widths say what sample bits mean.
    let mut fmts = p.masks[HW_PARAM_FORMAT];
    for f in p.masks[HW_PARAM_FORMAT].values() {
        if format_widths(f).is_none() {
            fmts.0[(f / 32) as usize] &= !(1 << (f % 32));
        }
    }
    p.masks[HW_PARAM_FORMAT].refine(&fmts);
    if p.masks[HW_PARAM_FORMAT].is_empty() {
        return Err(Empty);
    }
    changed(&mut cm, HW_PARAM_CHANNELS, p.interval_mut(HW_PARAM_CHANNELS).refine(&hw.channels))?;
    changed(&mut cm, HW_PARAM_RATE, p.interval_mut(HW_PARAM_RATE).refine_list(hw.rates.as_slice()))?;
    changed(&mut cm, HW_PARAM_PERIOD_BYTES, p.interval_mut(HW_PARAM_PERIOD_BYTES).refine(&hw.period_bytes))?;
    changed(&mut cm, HW_PARAM_PERIODS, p.interval_mut(HW_PARAM_PERIODS).refine(&hw.periods))?;
    let buf_max = Interval::whole(0, hw.buffer_bytes_max);
    changed(&mut cm, HW_PARAM_BUFFER_BYTES, p.interval_mut(HW_PARAM_BUFFER_BYTES).refine(&buf_max))?;
    // Counts and sizes are whole numbers.
    for q in [
        HW_PARAM_SAMPLE_BITS,
        HW_PARAM_FRAME_BITS,
        HW_PARAM_CHANNELS,
        HW_PARAM_RATE,
        HW_PARAM_PERIOD_SIZE,
        HW_PARAM_PERIOD_BYTES,
        HW_PARAM_PERIODS,
        HW_PARAM_BUFFER_SIZE,
        HW_PARAM_BUFFER_BYTES,
    ] {
        let mut w = Interval::FULL;
        w.integer = true;
        changed(&mut cm, q, p.interval_mut(q).refine(&w))?;
    }

    // The relations, until nothing changes.
    for _ in 0..100 {
        let mut round = 0u32;
        // Sample bits from the formats, and formats from sample bits.
        let mut lo = u32::MAX;
        let mut hi = 0;
        for f in p.masks[HW_PARAM_FORMAT].values() {
            let (_, phys) = format_widths(f).ok_or(Empty)?;
            lo = lo.min(phys);
            hi = hi.max(phys);
        }
        changed(
            &mut round,
            HW_PARAM_SAMPLE_BITS,
            p.interval_mut(HW_PARAM_SAMPLE_BITS).refine(&Interval::whole(lo, hi)),
        )?;
        let sb = *p.interval(HW_PARAM_SAMPLE_BITS);
        let mut keep = Mask::NONE;
        for f in p.masks[HW_PARAM_FORMAT].values() {
            let phys = format_widths(f).map_or(0, |w| w.1);
            if phys >= sb.least() && phys <= sb.most() {
                keep.set(f);
            }
        }
        if p.masks[HW_PARAM_FORMAT].refine(&keep) {
            round |= 1 << HW_PARAM_FORMAT;
        }
        if p.masks[HW_PARAM_FORMAT].is_empty() {
            return Err(Empty);
        }
        // Period bytes and the hardware's alignment.
        changed(&mut round, HW_PARAM_PERIOD_BYTES, p.interval_mut(HW_PARAM_PERIOD_BYTES).refine_step(hw.period_align))?;

        let iv = |p: &HwParams, q: usize| *p.interval(q);
        let rules: [(usize, Interval); 21] = [
            (HW_PARAM_FRAME_BITS, mul(&iv(p, HW_PARAM_SAMPLE_BITS), &iv(p, HW_PARAM_CHANNELS))),
            (HW_PARAM_SAMPLE_BITS, div(&iv(p, HW_PARAM_FRAME_BITS), &iv(p, HW_PARAM_CHANNELS))),
            (HW_PARAM_CHANNELS, div(&iv(p, HW_PARAM_FRAME_BITS), &iv(p, HW_PARAM_SAMPLE_BITS))),
            (HW_PARAM_PERIOD_BYTES, muldivk(&iv(p, HW_PARAM_PERIOD_SIZE), &iv(p, HW_PARAM_FRAME_BITS), 8)),
            (HW_PARAM_PERIOD_SIZE, mulkdiv(&iv(p, HW_PARAM_PERIOD_BYTES), 8, &iv(p, HW_PARAM_FRAME_BITS))),
            (HW_PARAM_FRAME_BITS, mulkdiv(&iv(p, HW_PARAM_PERIOD_BYTES), 8, &iv(p, HW_PARAM_PERIOD_SIZE))),
            (HW_PARAM_BUFFER_BYTES, muldivk(&iv(p, HW_PARAM_BUFFER_SIZE), &iv(p, HW_PARAM_FRAME_BITS), 8)),
            (HW_PARAM_BUFFER_SIZE, mulkdiv(&iv(p, HW_PARAM_BUFFER_BYTES), 8, &iv(p, HW_PARAM_FRAME_BITS))),
            (HW_PARAM_FRAME_BITS, mulkdiv(&iv(p, HW_PARAM_BUFFER_BYTES), 8, &iv(p, HW_PARAM_BUFFER_SIZE))),
            (HW_PARAM_BUFFER_SIZE, mul(&iv(p, HW_PARAM_PERIOD_SIZE), &iv(p, HW_PARAM_PERIODS))),
            (HW_PARAM_PERIOD_SIZE, div(&iv(p, HW_PARAM_BUFFER_SIZE), &iv(p, HW_PARAM_PERIODS))),
            (HW_PARAM_PERIODS, div(&iv(p, HW_PARAM_BUFFER_SIZE), &iv(p, HW_PARAM_PERIOD_SIZE))),
            (HW_PARAM_PERIOD_TIME, mulkdiv(&iv(p, HW_PARAM_PERIOD_SIZE), 1_000_000, &iv(p, HW_PARAM_RATE))),
            (HW_PARAM_PERIOD_SIZE, muldivk(&iv(p, HW_PARAM_PERIOD_TIME), &iv(p, HW_PARAM_RATE), 1_000_000)),
            (HW_PARAM_RATE, mulkdiv(&iv(p, HW_PARAM_PERIOD_SIZE), 1_000_000, &iv(p, HW_PARAM_PERIOD_TIME))),
            (HW_PARAM_BUFFER_TIME, mulkdiv(&iv(p, HW_PARAM_BUFFER_SIZE), 1_000_000, &iv(p, HW_PARAM_RATE))),
            (HW_PARAM_BUFFER_SIZE, muldivk(&iv(p, HW_PARAM_BUFFER_TIME), &iv(p, HW_PARAM_RATE), 1_000_000)),
            (HW_PARAM_RATE, mulkdiv(&iv(p, HW_PARAM_BUFFER_SIZE), 1_000_000, &iv(p, HW_PARAM_BUFFER_TIME))),
            (HW_PARAM_PERIODS, div(&iv(p, HW_PARAM_BUFFER_BYTES), &iv(p, HW_PARAM_PERIOD_BYTES))),
            (HW_PARAM_PERIOD_BYTES, div(&iv(p, HW_PARAM_BUFFER_BYTES), &iv(p, HW_PARAM_PERIODS))),
            (HW_PARAM_BUFFER_BYTES, mul(&iv(p, HW_PARAM_PERIOD_BYTES), &iv(p, HW_PARAM_PERIODS))),
        ];
        for (q, r) in rules {
            changed(&mut round, q, p.interval_mut(q).refine(&r))?;
        }
        // The rate stays one of the hardware's.
        changed(&mut round, HW_PARAM_RATE, p.interval_mut(HW_PARAM_RATE).refine_list(hw.rates.as_slice()))?;
        if round == 0 {
            break;
        }
    }

    // What becomes known once these are.
    p.info = hw.info;
    if p.msbits == 0
        && let Some(f) = p.masks[HW_PARAM_FORMAT].single()
    {
        let bits = format_widths(f).map_or(0, |w| w.0);
        p.msbits = if bits == 32 && hw.msbits32 != 0 { hw.msbits32 } else { bits };
    }
    if p.rate_den == 0
        && let Some(r) = p.interval(HW_PARAM_RATE).single()
    {
        p.rate_num = r;
        p.rate_den = 1;
    }
    // Only real changes count (a rule may narrow and another restore).
    p.cmask = 0;
    for m in 0..3 {
        if p.masks[m] != before.masks[m] {
            p.cmask |= 1 << m;
        }
    }
    for q in HW_PARAM_FIRST_INTERVAL..=HW_PARAM_LAST_INTERVAL {
        if p.interval(q) != before.interval(q) {
            p.cmask |= 1 << q;
        }
    }
    p.rmask = 0;
    Ok(())
}

/// Pick one configuration from what is left, as `HW_PARAMS` does for
/// parameters the program left open: the first access type and format,
/// the fewest channels and the lowest rate, the shortest period, and the
/// largest buffer (Slate's choice: fewer underruns).
pub fn choose(p: &mut HwParams, hw: &Hardware) -> Result<(), Empty> {
    refine(p, hw)?;
    for m in [HW_PARAM_ACCESS, HW_PARAM_FORMAT, HW_PARAM_SUBFORMAT] {
        if p.masks[m].single().is_none() {
            let v = p.masks[m].first().ok_or(Empty)?;
            p.masks[m] = Mask::of(&[v]);
            refine(p, hw)?;
        }
    }
    // Sizes, not times: a time picked first may hold no whole number of
    // frames; the times follow from the sizes.
    let order = [
        (HW_PARAM_CHANNELS, false),
        (HW_PARAM_RATE, false),
        (HW_PARAM_PERIOD_SIZE, false),
        (HW_PARAM_BUFFER_SIZE, true),
        (HW_PARAM_PERIODS, false),
    ];
    for (q, largest) in order {
        let iv = *p.interval(q);
        if iv.single().is_some() {
            continue;
        }
        let v = if largest { iv.most() } else { iv.least() };
        // A real-valued time takes the range [v, v + 1).
        p.interval_mut(q).refine(&Interval::value(v))?;
        refine(p, hw)?;
    }
    // TICK_TIME is unused: leave it as the program had it.
    for q in [HW_PARAM_CHANNELS, HW_PARAM_RATE, HW_PARAM_PERIOD_SIZE, HW_PARAM_BUFFER_SIZE, HW_PARAM_SAMPLE_BITS] {
        if p.interval(q).single().is_none() {
            return Err(Empty);
        }
    }
    Ok(())
}

/// The configuration hw_params settled on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setup {
    pub access: u32,
    pub format: u32,
    pub channels: u32,
    pub rate: u32,
    pub period_size: u32,
    pub periods: u32,
    pub buffer_size: u32,
    pub frame_bytes: u32,
    pub sample_bits: u32,
    pub msbits: u32,
    pub no_period_wakeup: bool,
}

impl Setup {
    /// Read the chosen configuration from a space with one left.
    pub fn from(p: &HwParams) -> Option<Setup> {
        let sample_bits = p.get(HW_PARAM_SAMPLE_BITS)?;
        let channels = p.get(HW_PARAM_CHANNELS)?;
        let period_size = p.get(HW_PARAM_PERIOD_SIZE)?;
        let buffer_size = p.get(HW_PARAM_BUFFER_SIZE)?;
        Some(Setup {
            access: p.get(HW_PARAM_ACCESS)?,
            format: p.get(HW_PARAM_FORMAT)?,
            channels,
            rate: p.get(HW_PARAM_RATE)?,
            period_size,
            periods: buffer_size / period_size.max(1),
            buffer_size,
            frame_bytes: sample_bits * channels / 8,
            sample_bits,
            msbits: p.msbits,
            no_period_wakeup: p.flags & HW_PARAMS_NO_PERIOD_WAKEUP != 0,
        })
    }

    pub fn buffer_bytes(&self) -> usize {
        self.buffer_size as usize * self.frame_bytes as usize
    }
    pub fn period_bytes(&self) -> usize {
        self.period_size as usize * self.frame_bytes as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hda() -> Hardware {
        Hardware {
            info: INFO_MMAP | INFO_MMAP_VALID | INFO_INTERLEAVED | INFO_BLOCK_TRANSFER | INFO_PAUSE,
            access: Mask::of(&[ACCESS_MMAP_INTERLEAVED, ACCESS_RW_INTERLEAVED]),
            formats: Mask::of(&[FORMAT_S16_LE, FORMAT_S32_LE]),
            msbits32: 24,
            channels: Interval::whole(2, 2),
            rates: alloc_free::Rates::of(&[44100, 48000, 96000]),
            period_bytes: Interval::whole(128, 2 << 20),
            period_align: 128,
            periods: Interval::whole(2, 32),
            buffer_bytes_max: 4 << 20,
        }
    }

    #[test]
    fn intervals_narrow_and_empty() {
        let mut a = Interval::range(10, 100);
        assert_eq!(a.refine(&Interval::range(20, 200)), Ok(true));
        assert_eq!((a.min, a.max), (20, 100));
        assert_eq!(a.refine(&Interval::range(0, 1000)), Ok(false));
        assert_eq!(a.refine(&Interval::range(101, 200)), Err(Empty));
        let mut b = Interval { min: 3, max: 4, openmin: true, openmax: false, integer: false, empty: false };
        assert_eq!(b.single(), Some(4));
        b.integer = true;
        let _ = b.refine(&Interval::FULL);
        assert_eq!((b.min, b.openmin), (4, false));
    }

    #[test]
    fn arithmetic_rounds_outwards() {
        let r = div(&Interval::range(10, 10), &Interval::range(3, 3));
        // 10/3 = 3.33: [3, 4], both ends open.
        assert_eq!((r.min, r.max, r.openmin, r.openmax), (3, 4, true, true));
        let r = muldivk(&Interval::range(1024, 1024), &Interval::range(32, 32), 8);
        assert_eq!((r.min, r.max, r.openmin, r.openmax), (4096, 4096, false, false));
        let r = mulkdiv(&Interval::range(1024, 1024), 1_000_000, &Interval::range(48000, 48000));
        // 21333.33 us.
        assert_eq!((r.min, r.max, r.openmin, r.openmax), (21333, 21334, true, true));
    }

    #[test]
    fn the_whole_space_narrows_to_the_hardware() {
        let hw = hda();
        let mut p = HwParams::any();
        refine(&mut p, &hw).unwrap();
        assert_eq!(p.interval(HW_PARAM_CHANNELS).single(), Some(2));
        assert_eq!(p.interval(HW_PARAM_SAMPLE_BITS).min, 16);
        assert_eq!(p.interval(HW_PARAM_SAMPLE_BITS).max, 32);
        assert_eq!(p.interval(HW_PARAM_FRAME_BITS).min, 32);
        assert_eq!(p.interval(HW_PARAM_RATE).min, 44100);
        assert_eq!(p.interval(HW_PARAM_RATE).max, 96000);
        // Periods of 128 bytes of 64-bit frames are 16 frames at least.
        assert_eq!(p.interval(HW_PARAM_PERIOD_SIZE).min, 16);
        assert!(p.cmask != 0);
        assert_eq!(p.info & INFO_MMAP, INFO_MMAP);
    }

    #[test]
    fn a_program_s_choices_settle_the_rest() {
        let hw = hda();
        let mut p = HwParams::any();
        refine(&mut p, &hw).unwrap();
        *p.mask_mut(HW_PARAM_ACCESS) = Mask::of(&[ACCESS_RW_INTERLEAVED]);
        *p.mask_mut(HW_PARAM_FORMAT) = Mask::of(&[FORMAT_S16_LE]);
        p.interval_mut(HW_PARAM_RATE).refine(&Interval::value(48000)).unwrap();
        p.interval_mut(HW_PARAM_PERIOD_SIZE).refine(&Interval::value(1024)).unwrap();
        p.interval_mut(HW_PARAM_PERIODS).refine(&Interval::value(4)).unwrap();
        refine(&mut p, &hw).unwrap();
        assert_eq!(p.get(HW_PARAM_SAMPLE_BITS), Some(16));
        assert_eq!(p.get(HW_PARAM_FRAME_BITS), Some(32));
        assert_eq!(p.get(HW_PARAM_PERIOD_BYTES), Some(4096));
        assert_eq!(p.get(HW_PARAM_BUFFER_SIZE), Some(4096));
        assert_eq!(p.get(HW_PARAM_BUFFER_BYTES), Some(16384));
        assert_eq!(p.get(HW_PARAM_PERIOD_TIME), Some(21333));
        assert_eq!((p.rate_num, p.rate_den, p.msbits), (48000, 1, 16));
        let s = Setup::from(&p).unwrap();
        assert_eq!((s.frame_bytes, s.periods, s.buffer_bytes()), (4, 4, 16384));
    }

    #[test]
    fn choosing_fills_in_what_is_open() {
        let hw = hda();
        let mut p = HwParams::any();
        *p.mask_mut(HW_PARAM_FORMAT) = Mask::of(&[FORMAT_S32_LE]);
        p.interval_mut(HW_PARAM_BUFFER_TIME).refine(&Interval::range(0, 100_000)).unwrap();
        choose(&mut p, &hw).unwrap();
        let s = Setup::from(&p).unwrap();
        assert_eq!((s.format, s.channels, s.rate, s.msbits), (FORMAT_S32_LE, 2, 44100, 24));
        assert_eq!(s.period_bytes() % 128, 0);
        assert!(s.buffer_size as u64 * 1_000_000 / u64::from(s.rate) <= 100_000);
        assert!(s.periods >= 2);
    }

    #[test]
    fn impossible_requests_are_refused() {
        let hw = hda();
        let mut p = HwParams::any();
        p.interval_mut(HW_PARAM_CHANNELS).refine(&Interval::value(6)).unwrap();
        assert_eq!(refine(&mut p, &hw), Err(Empty));
        let mut p = HwParams::any();
        p.interval_mut(HW_PARAM_RATE).refine(&Interval::value(22050)).unwrap();
        assert_eq!(refine(&mut p, &hw), Err(Empty));
        let mut p = HwParams::any();
        *p.mask_mut(HW_PARAM_FORMAT) = Mask::of(&[FORMAT_FLOAT_LE]);
        assert_eq!(refine(&mut p, &hw), Err(Empty));
    }

    #[test]
    fn the_structure_round_trips() {
        let hw = hda();
        let mut p = HwParams::any();
        refine(&mut p, &hw).unwrap();
        let mut buf = [0xaau8; HW_PARAMS_SIZE];
        p.encode(&mut buf);
        assert_eq!(HwParams::decode(&buf), p);
        // The reserved masks and intervals are left alone.
        assert_eq!(buf[4 + 3 * 32], 0xaa);
        assert_eq!(buf[260 + 12 * 12], 0xaa);
    }
}
