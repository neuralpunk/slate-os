// SPDX-License-Identifier: MIT OR Apache-2.0

//! The style guide's type roles on the window surface: a visual check of
//! font rendering. With SLATE_UI_OUT set, the picture is saved there.

use slate_ui::color::Color;
use slate_ui::text::{self, Face, GlyphCache, Style};
use slate_ui::{Canvas, png};

const WINDOW: Color = Color::rgb(0xF3F2F2);
const INK: Color = Color::rgb(0x0B0B0B);
const TEXT_3: Color = Color::rgb(0x5E5E5E);

fn font(name: &str) -> &'static [u8] {
    let path = format!("{}/../../assets/fonts/{name}", env!("CARGO_MANIFEST_DIR"));
    Box::leak(std::fs::read(path).unwrap().into_boxed_slice())
}

#[test]
fn specimen() {
    let g400 = Face::new(font("HostGrotesk-400.ttf"), 1).unwrap();
    let g500 = Face::new(font("HostGrotesk-500.ttf"), 2).unwrap();
    let g800 = Face::new(font("HostGrotesk-800.ttf"), 4).unwrap();
    let mono = Face::new(font("DMMono-Regular.ttf"), 5).unwrap();
    let mut c = Canvas::new(860, 420, WINDOW);
    let mut cache = GlyphCache::new();

    // "Welcome to SlateOS": 36/1.15, weight 500 with "OS" at 800, centred.
    let head = Style::new(&g500, 36.0, INK).tracking(-0.035);
    let os = Style::new(&g800, 36.0, INK).tracking(-0.02);
    let w = text::width(&head, "Welcome to Slate") + text::width(&os, "OS");
    let x = (860.0 - w) / 2.0;
    let base = 40.0 + g500.baseline(36.0, 41.4);
    let adv = text::draw(&mut c, &mut cache, &head, x, base, "Welcome to Slate");
    text::draw(&mut c, &mut cache, &os, x + adv, base, "OS");

    // The supporting line, 15/1.5 text-3, at most 440 wide, centred.
    let body = Style::new(&g400, 15.0, TEXT_3);
    let msg = "A secure, Linux-like system written from scratch in Rust. Stay locked down in Slate mode, or switch on Linux compatibility when you need it.";
    let mut top = 100.0;
    for line in text::wrap(&body, msg, 440.0) {
        let lw = text::width(&body, &line);
        text::draw(&mut c, &mut cache, &body, (860.0 - lw) / 2.0, top + g400.baseline(15.0, 22.5), &line);
        top += 22.5;
    }

    // Step heading, row title, button label, metadata.
    let step = Style::new(&g500, 28.0, INK).tracking(-0.03);
    text::draw(&mut c, &mut cache, &step, 44.0, 220.0, "Where should SlateOS be installed?");
    text::draw(&mut c, &mut cache, &Style::new(&g500, 15.0, INK), 44.0, 270.0, "NVMe SSD");
    text::draw(&mut c, &mut cache, &Style::new(&mono, 12.5, TEXT_3), 44.0, 288.0, "nvme0n1");
    text::draw(&mut c, &mut cache, &Style::new(&mono, 13.0, TEXT_3), 760.0, 278.0, "1 TB");
    text::draw(&mut c, &mut cache, &Style::new(&g500, 14.0, INK), 44.0, 330.0, "Install SlateOS");
    text::draw(&mut c, &mut cache, &Style::new(&g400, 14.5, INK), 44.0, 360.0, "English (United States)");
    text::draw(&mut c, &mut cache, &Style::new(&mono, 11.5, TEXT_3), 44.0, 390.0, "01  02  03  04  05");

    // Some ink landed where the heading is, none in the margins.
    let inked = (0..860).filter(|&x| c.pixel(x, base as i32 - 10) != 0xFFF3_F2F2).count();
    assert!(inked > 100, "heading pixels {inked}");
    assert_eq!(c.pixel(5, 5), 0xFFF3_F2F2);
    if let Ok(out) = std::env::var("SLATE_UI_OUT") {
        std::fs::write(out, png::encode(&c)).unwrap();
    }
}
