// SPDX-License-Identifier: MIT OR Apache-2.0

//! HD Audio codecs (ADR 0184): [`verb`] has the verbs and parameters of
//! Intel's High Definition Audio Specification (revision 1.0a), [`graph`]
//! reads a codec's widgets and chooses the paths Slate plays and records
//! through, and [`sim`] is a codec made of a widget list, for tests. The
//! controller itself (CORB, RIRB, streams) is the kernel's driver.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod graph;
pub mod sim;
pub mod verb;

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::graph::*;
    use crate::sim::*;
    use crate::verb::*;

    /// A converter widget: stereo, its format and amplifier given here.
    fn conv(nid: u8, kind: u32, conns: Vec<u8>, amp: u32) -> Widget {
        let mut bits = CAP_STEREO | CAP_FORMAT_OVERRIDE;
        if !conns.is_empty() {
            bits |= CAP_CONN_LIST;
        }
        if amp != 0 {
            bits |= CAP_AMP_OVERRIDE | if kind == WIDGET_OUTPUT { CAP_OUT_AMP } else { CAP_IN_AMP };
        }
        let mut w = Widget { nid, caps: caps(kind, bits), conns, pcm: 0x000e_0060, formats: 1, ..Widget::default() };
        if kind == WIDGET_OUTPUT {
            w.amp_out = AmpCaps(amp);
        } else {
            w.amp_in = AmpCaps(amp);
        }
        w
    }

    fn pin(nid: u8, conns: Vec<u8>, pin_caps: u32, cfg: u32) -> Widget {
        let bits = CAP_STEREO | if conns.is_empty() { 0 } else { CAP_CONN_LIST };
        Widget { nid, caps: caps(WIDGET_PIN, bits), conns, pin_caps, config: cfg, ..Widget::default() }
    }

    /// A line out and a line in, each straight to its converter.
    fn simple() -> SimCodec {
        SimCodec {
            vendor: 0x1af4_0022,
            afg: 1,
            widgets: vec![
                conv(2, WIDGET_OUTPUT, vec![], 0x8000_4a4a),
                pin(3, vec![2], PIN_OUTPUT, config(0, DEV_LINE_OUT, 1, 0)),
                conv(4, WIDGET_INPUT, vec![5], 0x8000_4a4a),
                pin(5, vec![], PIN_INPUT, config(0, DEV_LINE_IN, 2, 0)),
            ],
            group_pcm: 0x000e_0060,
            group_amp_out: 0,
            group_amp_in: 0,
            sets: Vec::new(),
        }
    }

    /// Two DACs through two mixers, a speaker and headphones that select
    /// between the mixers, a microphone through a selector to the ADC, an
    /// HDMI pin and a pin with nothing attached.
    fn laptop() -> SimCodec {
        let amp = 0x8005_4a4a;
        let mixer = |nid, conns| Widget {
            nid,
            caps: caps(WIDGET_MIXER, CAP_STEREO | CAP_IN_AMP | CAP_CONN_LIST),
            conns,
            amp_in: AmpCaps(0x8000_0000),
            ..Widget::default()
        };
        SimCodec {
            vendor: 0x10ec_0897,
            afg: 1,
            widgets: vec![
                conv(0x02, WIDGET_OUTPUT, vec![], amp),
                conv(0x03, WIDGET_OUTPUT, vec![], amp),
                conv(0x08, WIDGET_INPUT, vec![0x23], 0),
                mixer(0x0c, vec![0x02, 0x0b]),
                mixer(0x0d, vec![0x03, 0x0b]),
                Widget { nid: 0x0b, caps: caps(WIDGET_MIXER, CAP_STEREO), ..Widget::default() },
                pin(0x14, vec![0x0c, 0x0d], PIN_OUTPUT | PIN_EAPD, config(2, DEV_SPEAKER, 1, 0)),
                pin(
                    0x15,
                    vec![0x0c, 0x0d],
                    PIN_OUTPUT | PIN_HEADPHONE_DRIVE | PIN_PRESENCE_DETECT,
                    config(0, DEV_HP_OUT, 1, 15),
                ),
                pin(0x16, vec![0x0c], PIN_OUTPUT, config(1, DEV_LINE_OUT, 15, 0)),
                pin(0x18, vec![], PIN_INPUT | PIN_VREF_80, config(0, DEV_MIC_IN, 3, 0)),
                pin(0x1e, vec![0x0d], PIN_OUTPUT | PIN_HDMI, config(0, DEV_DIGITAL_OUT, 4, 0)),
                Widget {
                    nid: 0x23,
                    caps: caps(WIDGET_SELECTOR, CAP_STEREO | CAP_CONN_LIST | CAP_IN_AMP | CAP_AMP_OVERRIDE),
                    conns: vec![0x0b, 0x18],
                    amp_in: AmpCaps(0x8003_2f00),
                    ..Widget::default()
                },
            ],
            group_pcm: 0x000e_0060,
            group_amp_out: 0,
            group_amp_in: 0,
            sets: Vec::new(),
        }
    }

    #[test]
    fn a_simple_codec() {
        let mut c = simple();
        let g = read(&mut c, 0).unwrap();
        assert_eq!((g.vendor, g.afg, g.widgets.len()), (0x1af4_0022, 1, 4));
        let p = plan(&g);
        assert_eq!(p.dac, Some(2));
        assert_eq!(p.outputs, vec![(Output::LineOut, Path(vec![2, 3]))]);
        assert_eq!((p.adc, p.input.clone()), (Some(4), Some(Path(vec![5, 4]))));
        assert_eq!(volume_amp(&g, &p.outputs[0].1, true), Some((2, true, 0, AmpCaps(0x8000_4a4a))));
        assert_eq!(volume_amp(&g, p.input.as_ref().unwrap(), false), Some((4, false, 0, AmpCaps(0x8000_4a4a))));
        let (rates, bits) = converter_formats(g.widget(2).unwrap());
        assert_eq!((rates, bits), (vec![44100, 48000], vec![16, 20, 24]));
        let v = setup_verbs(&g, &p);
        // The DAC's amplifier at 0 dB, the pin's output on, the line in's
        // input on, the ADC's input amplifier at 0 dB.
        assert!(v.contains(&verb4(0, 2, SET_AMP_GAIN_MUTE, 0xb04a)));
        assert!(v.contains(&verb12(0, 3, SET_PIN_CONTROL, PINCTL_OUT_ENABLE)));
        assert!(v.contains(&verb12(0, 5, SET_PIN_CONTROL, PINCTL_IN_ENABLE)));
        assert!(v.contains(&verb4(0, 4, SET_AMP_GAIN_MUTE, 0x704a)));
    }

    #[test]
    fn a_laptop_codec() {
        let mut c = laptop();
        let g = read(&mut c, 2).unwrap();
        let p = plan(&g);
        // The first DAC reaches both the speaker and the headphones; the
        // line out has nothing attached and the HDMI pin is digital.
        assert_eq!(p.dac, Some(0x02));
        assert_eq!(
            p.outputs,
            vec![(Output::Speaker, Path(vec![0x02, 0x0c, 0x14])), (Output::Headphone, Path(vec![0x02, 0x0c, 0x15]))]
        );
        assert_eq!((p.adc, p.input.clone()), (Some(0x08), Some(Path(vec![0x18, 0x23, 0x08]))));
        let v = setup_verbs(&g, &p);
        let has = |x| v.contains(&x);
        assert!(has(verb12(2, 0x14, SET_CONNECTION_SELECT, 0)));
        assert!(has(verb12(2, 0x14, SET_EAPD, EAPD_ENABLE)));
        assert!(has(verb12(2, 0x15, SET_PIN_CONTROL, PINCTL_OUT_ENABLE | PINCTL_HP_ENABLE)));
        assert!(has(verb12(2, 0x14, SET_PIN_CONTROL, PINCTL_OUT_ENABLE)));
        // The mixer's DAC input on, its loopback input muted.
        assert!(has(verb4(2, 0x0c, SET_AMP_GAIN_MUTE, amp_payload(false, 0, 0, false, true, true))));
        assert!(has(verb4(2, 0x0c, SET_AMP_GAIN_MUTE, amp_payload(false, 1, 0, true, true, true))));
        // The selector picks the microphone; the microphone gets its bias.
        assert!(has(verb12(2, 0x23, SET_CONNECTION_SELECT, 1)));
        assert!(has(verb12(2, 0x18, SET_PIN_CONTROL, PINCTL_IN_ENABLE | PINCTL_VREF_80)));
        assert!(!v.iter().any(|x| (x >> 20) & 0xff == 0x1e));
        // The volume: the DAC's own amplifier; for recording, the
        // selector's input amplifier on the microphone's input.
        assert_eq!(volume_amp(&g, &p.outputs[0].1, true).map(|a| a.0), Some(0x02));
        assert_eq!(volume_amp(&g, p.input.as_ref().unwrap(), false).map(|a| (a.0, a.1, a.2)), Some((0x23, false, 1)));
    }

    #[test]
    fn long_and_ranged_connection_lists() {
        let mut c = simple();
        // Entries 2, then a range up to 5 (bit 7 set).
        c.widgets[1].conns = vec![0x02, 0x85];
        let g = read(&mut c, 0).unwrap();
        assert_eq!(g.widget(3).unwrap().conns, vec![2, 3, 4, 5]);
    }

    #[test]
    fn no_audio_group() {
        let mut c = simple();
        c.afg = 9;
        c.widgets.clear();
        assert!(read(&mut c, 0).is_none_or(|g| plan(&g).dac.is_none()));
    }
}
