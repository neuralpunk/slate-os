// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Disk screen's shapes (no text yet), at scale 1: a visual check of
//! the rendering core. With SLATE_UI_OUT set, the picture is saved there.

use slate_ui::color::Color;
use slate_ui::path::{Path, Transform};
use slate_ui::shadow::{self, BoxShadow};
use slate_ui::{Canvas, Rect, logo, png, stroke};

const DESKTOP: Color = Color::rgb(0xDCDBDB);
const WINDOW: Color = Color::rgb(0xF3F2F2);
const SIDEBAR: Color = Color::rgb(0xEEEDED);
const HAIRLINE: Color = Color::rgb(0xDEDDDD);
const BORDER: Color = Color::rgb(0xCFCECE);
const BORDER_ROW: Color = Color::rgb(0xD4D3D3);
const INK: Color = Color::rgb(0x0B0B0B);
const ON_INK: Color = Color::rgb(0xF3F2F2);

fn outline(c: &mut Canvas, (x, y, w, h): (f32, f32, f32, f32), r: f32, width: f32, color: Color) {
    Path::rounded_ring(x, y, w, h, r, width).fill(c, &Transform::IDENTITY, color);
}

fn draw() -> Canvas {
    let mut c = Canvas::new(1280, 800, DESKTOP);
    let (wx, wy, ww, wh) = (210.0, 120.0, 860.0, 560.0);
    for s in [
        BoxShadow { dx: 0.0, dy: 40.0, blur: 90.0, spread: -30.0, color: Color::rgb(0).with_alpha(89) },
        BoxShadow { dx: 0.0, dy: 2.0, blur: 6.0, spread: 0.0, color: Color::rgb(0).with_alpha(15) },
        BoxShadow { dx: 0.0, dy: 0.0, blur: 0.0, spread: 1.0, color: Color::rgb(0).with_alpha(20) },
    ] {
        shadow::draw(&mut c, wx, wy, ww, wh, 12.0, &s);
    }
    Path::rounded_rect(wx, wy, ww, wh, 12.0).fill(&mut c, &Transform::IDENTITY, WINDOW);
    // Title bar divider, sidebar and its divider.
    let old = c.set_clip(Rect::new(wx as i32, wy as i32, ww as i32, wh as i32));
    c.fill_rect(Rect::new(210, 163, 860, 1), HAIRLINE);
    Path::rounded_rect(wx, 164.0, 196.0, 516.0, 12.0).fill(&mut c, &Transform::IDENTITY, SIDEBAR);
    c.fill_rect(Rect::new(210 + 12, 164, 184, 12), SIDEBAR);
    c.fill_rect(Rect::new(406, 164, 1, 516), HAIRLINE);
    c.set_clip(old);
    logo::draw(&mut c, 226.0, 134.0, 16.0, INK);
    // The current step's bar.
    c.fill_rect(Rect::new(210, 230, 2, 38), INK);
    // Choice rows: selected, then unselected.
    let (rx, rw) = (450.0, 576.0);
    Path::rounded_rect(rx, 260.0, rw, 64.0, 8.0).fill(&mut c, &Transform::IDENTITY, INK);
    Path::circle(rx + 24.0, 292.0, 6.0).fill(&mut c, &Transform::IDENTITY, ON_INK);
    outline(&mut c, (rx, 332.0, rw, 64.0), 8.0, 1.0, BORDER_ROW);
    outline(&mut c, (rx + 18.0, 358.0, 12.0, 12.0), 6.0, 1.5, INK);
    // Checked checkbox with its tick.
    Path::rounded_rect(rx, 416.0, 16.0, 16.0, 4.0).fill(&mut c, &Transform::IDENTITY, INK);
    stroke::polyline(&[(rx + 4.0, 424.0), (rx + 7.0, 427.0), (rx + 12.5, 420.5)], 1.8).fill(
        &mut c,
        &Transform::IDENTITY,
        ON_INK,
    );
    // Back (secondary) and Continue (primary).
    outline(&mut c, (882.0, 624.0, 76.0, 40.0), 8.0, 1.0, BORDER);
    Path::rounded_rect(968.0, 624.0, 100.0, 40.0, 8.0).fill(&mut c, &Transform::IDENTITY, INK);
    // The welcome-size mark, for comparison.
    logo::draw(&mut c, 40.0, 40.0, 56.0, INK);
    c
}

#[test]
fn disk_screen_shapes() {
    let c = draw();
    // Spot checks: backdrop, window, sidebar, selected row, shadow below.
    assert_eq!(c.pixel(5, 5), 0xFFDC_DBDB);
    assert_eq!(c.pixel(700, 500), 0xFFF3_F2F2);
    assert_eq!(c.pixel(300, 500), 0xFFEE_EDED);
    assert_eq!(c.pixel(700, 280), 0xFF0B_0B0B);
    let below = c.pixel(640, 700) & 0xFF;
    assert!(below < 0xDB, "a shadow under the window ({below:#x})");
    if let Ok(out) = std::env::var("SLATE_UI_OUT") {
        std::fs::write(out, png::encode(&c)).unwrap();
    }
}
