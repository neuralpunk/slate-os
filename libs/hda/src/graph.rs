// SPDX-License-Identifier: MIT OR Apache-2.0

//! A codec's audio function group as a graph of widgets, and the paths
//! Slate plays and records through (ADR 0184).
//!
//! Every widget lists the widgets it takes input from (its connection
//! list, §7.1.3). Playback goes from an output converter (a DAC) through
//! mixers and selectors to output pins; recording from an input pin to an
//! input converter (an ADC). Which pins are outputs, and what they are
//! (line out, speaker, headphones, microphone), comes from each pin's
//! configuration default, which the board's firmware sets (§7.3.3.31).
//! Digital pins (HDMI, DisplayPort, S/PDIF) are left out.

use alloc::vec::Vec;

use crate::verb::*;

/// Something that runs a verb on a codec and returns its response (None:
/// no response came).
pub trait Codec {
    fn cmd(&mut self, verb: u32) -> Option<u32>;
}

/// A widget of the audio function group.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Widget {
    pub nid: u8,
    pub caps: u32,
    /// Widgets it takes input from, in its connection list's order.
    pub conns: Vec<u8>,
    pub pin_caps: u32,
    pub config: u32,
    pub amp_in: AmpCaps,
    pub amp_out: AmpCaps,
    /// Sizes and rates, and stream formats (the group's if the widget
    /// doesn't override them).
    pub pcm: u32,
    pub formats: u32,
}

impl Widget {
    pub fn kind(&self) -> u32 {
        (self.caps >> 20) & 0xf
    }
    pub fn digital(&self) -> bool {
        self.caps & CAP_DIGITAL != 0
    }
    pub fn stereo(&self) -> bool {
        self.caps & CAP_STEREO != 0
    }
    pub fn has_in_amp(&self) -> bool {
        self.caps & CAP_IN_AMP != 0
    }
    pub fn has_out_amp(&self) -> bool {
        self.caps & CAP_OUT_AMP != 0
    }
    /// The pin's default device (line out, speaker...).
    pub fn device(&self) -> u32 {
        (self.config >> 20) & 0xf
    }
    /// Whether the firmware says something is (or can be) attached.
    pub fn connected(&self) -> bool {
        self.config >> 30 != PORT_NONE
    }
}

/// An audio function group.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Graph {
    pub cad: u8,
    pub vendor: u32,
    pub afg: u8,
    pub widgets: Vec<Widget>,
}

impl Graph {
    pub fn widget(&self, nid: u8) -> Option<&Widget> {
        self.widgets.iter().find(|w| w.nid == nid)
    }
}

fn param(c: &mut dyn Codec, cad: u8, nid: u8, p: u8) -> Option<u32> {
    c.cmd(verb12(cad, nid, GET_PARAMETER, p))
}

/// A widget's connection list (§7.3.3.3): entries four at a time in the
/// short form (8 bits each), two at a time in the long form (16 bits);
/// an entry with bit 7 (15) set is a range from the previous entry.
fn connections(c: &mut dyn Codec, cad: u8, nid: u8) -> Vec<u8> {
    let Some(len) = param(c, cad, nid, PARAM_CONNECTION_LIST_LENGTH) else { return Vec::new() };
    let long = len & 0x80 != 0;
    let n = (len & 0x7f) as usize;
    let (per, bits) = if long { (2, 16) } else { (4, 8) };
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < n {
        let Some(r) = c.cmd(verb12(cad, nid, GET_CONNECTION_LIST, i as u8)) else { break };
        for k in 0..per {
            if i + k >= n {
                break;
            }
            let e = (r >> (k * bits)) & ((1 << bits) - 1);
            let range = e & (1 << (bits - 1)) != 0;
            let id = (e & ((1 << (bits - 1)) - 1)) as u8;
            match (range, out.last().copied()) {
                (true, Some(prev)) if id > prev => out.extend(prev + 1..=id),
                _ => out.push(id),
            }
        }
        i += per;
    }
    out
}

/// Read the codec at address `cad`: its first audio function group and
/// that group's widgets. None if it has none (a modem codec).
pub fn read(c: &mut dyn Codec, cad: u8) -> Option<Graph> {
    let vendor = param(c, cad, 0, PARAM_VENDOR_ID)?;
    let sub = param(c, cad, 0, PARAM_SUBORDINATE_COUNT)?;
    let (start, count) = (((sub >> 16) & 0xff) as u8, (sub & 0xff) as u8);
    let afg = (start..start.saturating_add(count))
        .find(|&n| param(c, cad, n, PARAM_FUNCTION_GROUP_TYPE).is_some_and(|t| t & 0xff == FG_AUDIO))?;
    let group_pcm = param(c, cad, afg, PARAM_PCM).unwrap_or(0);
    let group_formats = param(c, cad, afg, PARAM_STREAM_FORMATS).unwrap_or(0);
    let group_in = AmpCaps(param(c, cad, afg, PARAM_AMP_IN_CAPS).unwrap_or(0));
    let group_out = AmpCaps(param(c, cad, afg, PARAM_AMP_OUT_CAPS).unwrap_or(0));
    let sub = param(c, cad, afg, PARAM_SUBORDINATE_COUNT)?;
    let (start, count) = (((sub >> 16) & 0xff) as u8, (sub & 0xff) as u8);
    let mut widgets = Vec::new();
    for nid in start..start.saturating_add(count) {
        let Some(caps) = param(c, cad, nid, PARAM_AUDIO_WIDGET_CAPS) else { continue };
        let mut w = Widget { nid, caps, ..Widget::default() };
        if caps & CAP_CONN_LIST != 0 {
            w.conns = connections(c, cad, nid);
        }
        let over = caps & CAP_AMP_OVERRIDE != 0;
        if w.has_in_amp() {
            w.amp_in = if over { AmpCaps(param(c, cad, nid, PARAM_AMP_IN_CAPS).unwrap_or(0)) } else { group_in };
        }
        if w.has_out_amp() {
            w.amp_out = if over { AmpCaps(param(c, cad, nid, PARAM_AMP_OUT_CAPS).unwrap_or(0)) } else { group_out };
        }
        if matches!(w.kind(), WIDGET_OUTPUT | WIDGET_INPUT) {
            let own = caps & CAP_FORMAT_OVERRIDE != 0;
            w.pcm = if own { param(c, cad, nid, PARAM_PCM).unwrap_or(group_pcm) } else { group_pcm };
            w.formats =
                if own { param(c, cad, nid, PARAM_STREAM_FORMATS).unwrap_or(group_formats) } else { group_formats };
        }
        if w.kind() == WIDGET_PIN {
            w.pin_caps = param(c, cad, nid, PARAM_PIN_CAPS).unwrap_or(0);
            w.config = c.cmd(verb12(cad, nid, GET_CONFIG_DEFAULT, 0)).unwrap_or(0);
        }
        widgets.push(w);
    }
    Some(Graph { cad, vendor, afg, widgets })
}

/// A path through the graph, converter first, pin last; each widget after
/// the first takes its input from the one before it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path(pub Vec<u8>);

/// What kind of output a pin is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    LineOut,
    Speaker,
    Headphone,
}

/// The paths Slate uses on a codec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// The DAC every output plays from.
    pub dac: Option<u8>,
    pub outputs: Vec<(Output, Path)>,
    /// The ADC and the path from the input pin to it (pin first here,
    /// ADC last).
    pub adc: Option<u8>,
    pub input: Option<Path>,
}

/// Paths from `from` (a converter) to `pin`, following who takes input
/// from whom, through mixers and selectors only; the shortest.
fn route_out(g: &Graph, dac: u8, pin: u8) -> Option<Path> {
    // Breadth first from the pin back to the DAC.
    let mut queue: Vec<Vec<u8>> = alloc::vec![alloc::vec![pin]];
    let mut seen: Vec<u8> = alloc::vec![pin];
    let mut i = 0;
    while i < queue.len() {
        let path = queue[i].clone();
        i += 1;
        if path.len() > 8 {
            continue;
        }
        let at = g.widget(*path.last()?)?;
        for &src in &at.conns {
            if seen.contains(&src) {
                continue;
            }
            seen.push(src);
            let Some(w) = g.widget(src) else { continue };
            let mut p = path.clone();
            p.push(src);
            if src == dac {
                p.reverse();
                return Some(Path(p));
            }
            if matches!(w.kind(), WIDGET_MIXER | WIDGET_SELECTOR) {
                queue.push(p);
            }
        }
    }
    None
}

/// The path from input `pin` to `adc` (pin first).
fn route_in(g: &Graph, adc: u8, pin: u8) -> Option<Path> {
    let mut queue: Vec<Vec<u8>> = alloc::vec![alloc::vec![adc]];
    let mut seen: Vec<u8> = alloc::vec![adc];
    let mut i = 0;
    while i < queue.len() {
        let path = queue[i].clone();
        i += 1;
        if path.len() > 8 {
            continue;
        }
        let at = g.widget(*path.last()?)?;
        for &src in &at.conns {
            if seen.contains(&src) {
                continue;
            }
            seen.push(src);
            let Some(w) = g.widget(src) else { continue };
            let mut p = path.clone();
            p.push(src);
            if src == pin {
                p.reverse();
                return Some(Path(p));
            }
            if matches!(w.kind(), WIDGET_MIXER | WIDGET_SELECTOR) {
                queue.push(p);
            }
        }
    }
    None
}

/// Analog output pins the firmware says are there, line outs first, then
/// speakers, then headphones.
fn output_pins(g: &Graph) -> Vec<(Output, u8)> {
    let mut pins: Vec<(Output, u8)> = g
        .widgets
        .iter()
        .filter(|w| {
            w.kind() == WIDGET_PIN
                && !w.digital()
                && w.pin_caps & PIN_OUTPUT != 0
                && w.pin_caps & (PIN_HDMI | PIN_DP) == 0
                && w.connected()
        })
        .filter_map(|w| {
            let o = match w.device() {
                DEV_LINE_OUT => Output::LineOut,
                DEV_SPEAKER => Output::Speaker,
                DEV_HP_OUT => Output::Headphone,
                _ => return None,
            };
            Some((o, w.nid))
        })
        .collect();
    pins.sort_by_key(|(o, nid)| (*o as u8, *nid));
    pins
}

/// Choose the paths: the analog DAC that reaches the most output pins
/// (ties: the first), every pin it reaches; an input pin (a microphone,
/// else line in) and an analog ADC that reaches it.
pub fn plan(g: &Graph) -> Plan {
    let mut p = Plan::default();
    let pins = output_pins(g);
    let dacs: Vec<u8> = g.widgets.iter().filter(|w| w.kind() == WIDGET_OUTPUT && !w.digital()).map(|w| w.nid).collect();
    let mut best: Option<(usize, u8)> = None;
    for &d in &dacs {
        let n = pins.iter().filter(|(_, pin)| route_out(g, d, *pin).is_some()).count();
        if n > 0 && best.is_none_or(|(m, _)| n > m) {
            best = Some((n, d));
        }
    }
    if let Some((_, dac)) = best {
        p.dac = Some(dac);
        for (o, pin) in pins {
            if let Some(path) = route_out(g, dac, pin) {
                p.outputs.push((o, path));
            }
        }
    }
    let mut ins: Vec<&Widget> = g
        .widgets
        .iter()
        .filter(|w| {
            w.kind() == WIDGET_PIN
                && !w.digital()
                && w.pin_caps & PIN_INPUT != 0
                && w.connected()
                && matches!(w.device(), DEV_MIC_IN | DEV_LINE_IN)
        })
        .collect();
    ins.sort_by_key(|w| (w.device() != DEV_MIC_IN, w.nid));
    'pins: for pin in ins {
        for adc in g.widgets.iter().filter(|w| w.kind() == WIDGET_INPUT && !w.digital()) {
            if let Some(path) = route_in(g, adc.nid, pin.nid) {
                p.adc = Some(adc.nid);
                p.input = Some(path);
                break 'pins;
            }
        }
    }
    p
}

/// The amplifier that sets a path's volume: the first on it, from the
/// converter's side, with more than one step (output amplifiers, and
/// input amplifiers on the path's inputs). Returns (nid, output?, index,
/// caps).
pub fn volume_amp(g: &Graph, path: &Path, playback: bool) -> Option<(u8, bool, u8, AmpCaps)> {
    let order: Vec<u8> = if playback { path.0.clone() } else { path.0.iter().rev().copied().collect() };
    for (i, &nid) in order.iter().enumerate() {
        let w = g.widget(nid)?;
        if w.has_out_amp() && w.amp_out.steps() > 0 {
            return Some((nid, true, 0, w.amp_out));
        }
        // An input amplifier on the input this path comes through.
        let from = if playback { i.checked_sub(1).map(|j| order[j]) } else { order.get(i + 1).copied() };
        if let Some(src) = from
            && w.has_in_amp()
            && w.amp_in.steps() > 0
            && let Some(idx) = w.conns.iter().position(|&c| c == src)
        {
            return Some((nid, false, idx as u8, w.amp_in));
        }
    }
    None
}

/// The verbs that switch a plan on: power, connection selects, every
/// amplifier on the paths unmuted at 0 dB, pins enabled (headphones with
/// their drive), EAPD where pins have it.
pub fn setup_verbs(g: &Graph, plan: &Plan) -> Vec<u32> {
    let cad = g.cad;
    let mut v = alloc::vec![verb12(cad, g.afg, SET_POWER_STATE, 0)];
    for w in g.widgets.iter().filter(|w| w.caps & CAP_POWER_CONTROL != 0) {
        v.push(verb12(cad, w.nid, SET_POWER_STATE, 0));
    }
    let zero_db = |a: AmpCaps| a.offset().min(a.steps());
    // Along a path (in signal order), each widget takes input from the one
    // before it.
    let wire = |v: &mut Vec<u32>, order: &[u8]| {
        for (i, &nid) in order.iter().enumerate() {
            let Some(w) = g.widget(nid) else { continue };
            if let Some(&src) = i.checked_sub(1).and_then(|j| order.get(j))
                && let Some(idx) = w.conns.iter().position(|&c| c == src)
            {
                if w.conns.len() > 1 && w.kind() != WIDGET_MIXER {
                    v.push(verb12(cad, nid, SET_CONNECTION_SELECT, idx as u8));
                }
                if w.has_in_amp() {
                    let on = amp_payload(false, idx as u8, zero_db(w.amp_in), false, true, true);
                    v.push(verb4(cad, nid, SET_AMP_GAIN_MUTE, on));
                    // A mixer's other inputs (an analog loopback from a
                    // microphone, say) stay muted.
                    if w.kind() == WIDGET_MIXER {
                        for other in (0..w.conns.len()).filter(|&k| k != idx) {
                            let off = amp_payload(false, other as u8, 0, true, true, true);
                            v.push(verb4(cad, nid, SET_AMP_GAIN_MUTE, off));
                        }
                    }
                }
            }
            if w.has_out_amp() {
                v.push(verb4(cad, nid, SET_AMP_GAIN_MUTE, amp_payload(true, 0, zero_db(w.amp_out), false, true, true)));
            }
        }
    };
    for (o, path) in &plan.outputs {
        wire(&mut v, &path.0);
        let pin = *path.0.last().unwrap_or(&0);
        let Some(w) = g.widget(pin) else { continue };
        let mut ctl = PINCTL_OUT_ENABLE;
        if *o == Output::Headphone && w.pin_caps & PIN_HEADPHONE_DRIVE != 0 {
            ctl |= PINCTL_HP_ENABLE;
        }
        v.push(verb12(cad, pin, SET_PIN_CONTROL, ctl));
        if w.pin_caps & PIN_EAPD != 0 {
            v.push(verb12(cad, pin, SET_EAPD, EAPD_ENABLE));
        }
    }
    if let Some(path) = &plan.input {
        wire(&mut v, &path.0);
        let pin = path.0[0];
        if let Some(w) = g.widget(pin) {
            let mut ctl = PINCTL_IN_ENABLE;
            if w.device() == DEV_MIC_IN {
                if w.pin_caps & PIN_VREF_80 != 0 {
                    ctl |= PINCTL_VREF_80;
                } else if w.pin_caps & PIN_VREF_50 != 0 {
                    ctl |= PINCTL_VREF_50;
                }
            }
            v.push(verb12(cad, pin, SET_PIN_CONTROL, ctl));
        }
    }
    v
}

/// The formats a converter takes: (rates, bits) from its PCM parameter,
/// PCM streams only (stream formats bit 0).
pub fn converter_formats(w: &Widget) -> (Vec<u32>, Vec<u32>) {
    if w.formats & 1 == 0 {
        return (Vec::new(), Vec::new());
    }
    (pcm_rates(w.pcm).collect(), pcm_bits(w.pcm).collect())
}
