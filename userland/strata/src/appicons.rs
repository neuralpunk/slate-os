// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux apps' own icons (M31 phase 4, ADR 0182): Flatpak exports each
//! app's icon beside its desktop entry, in the icon theme's layout
//! (freedesktop's Icon Theme Specification: `icons/hicolor/SIZExSIZE/
//! apps/NAME.png` under the same `share`). The launcher shows it in the
//! app's row, and its windows in their title bars. PNGs only: for a
//! Flatpak app whose icon is only scalable (SVG, as GNOME's are), the
//! PNG Flathub's catalog carries for it (`appstream/REMOTE/ARCH/active/
//! icons/SIZE/ID.png`, which slate-flatpak fetches after an install), else
//! the generic glyph.

use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;

use slate_image::Image;
use slate_rt::fs;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

/// The sizes looked for, best first: big enough for the launcher at
/// scale 2, small enough to decode quickly.
const SIZES: [u32; 7] = [64, 96, 128, 48, 256, 32, 512];
/// Icons are kept at most this size (pixels), shrunk once when loaded.
const KEPT: u32 = 96;

/// The icon file for `name` (an entry's `Icon=`) beside the desktop
/// entries in `apps_dir` (`.../share/applications`), if there is one.
pub fn resolve(apps_dir: &str, name: &str) -> Option<String> {
    // A name, not a path (the specification allows a path; exported
    // entries name their icon).
    if name.is_empty() || name.contains('/') || name.starts_with('.') {
        return None;
    }
    let share = apps_dir.trim_end_matches('/').strip_suffix("/applications")?;
    SIZES.iter().map(|s| format!("{share}/icons/hicolor/{s}x{s}/apps/{name}.png")).find(|p| fs::exists(p.as_bytes()))
}

/// A Flatpak app's icon from its remotes' catalogs (the person's
/// installation, then the system's), if one has it.
pub fn from_catalog(id: &str) -> Option<String> {
    let home = slate_rt::env::var(b"HOME").map(|h| String::from(slate_rt::lossy(&h))).unwrap_or_default();
    let roots = [
        format!("{home}/.local/share/flatpak/appstream"),
        String::from("/var/lib/slate/linux/var/lib/flatpak/appstream"),
    ];
    for root in roots {
        for remote in fs::read_dir(root.as_bytes()).unwrap_or_default() {
            let remote = String::from(slate_rt::lossy(&remote.name));
            if remote.starts_with('.') {
                continue;
            }
            for size in ["64x64", "128x128"] {
                let p = format!("{root}/{remote}/x86_64/active/icons/{size}/{id}.png");
                if fs::exists(p.as_bytes()) {
                    return Some(p);
                }
            }
        }
    }
    None
}

/// The icon decoded, shrunk to at most [`KEPT`] pixels across.
pub fn load(path: &str) -> Option<Rc<Image>> {
    let data = fs::read_file(path.as_bytes()).ok()?;
    if data.len() > 4 << 20 {
        return None;
    }
    let img = slate_image::decode(&data).ok()?;
    let big = img.width.max(img.height);
    let img =
        if big > KEPT { img.scaled((img.width * KEPT / big).max(1), (img.height * KEPT / big).max(1)) } else { img };
    Some(Rc::new(img))
}

/// Where Flatpak exports entries: the person's installation, then the
/// system's in the Linux runtime.
fn export_dirs() -> [String; 2] {
    let home = slate_rt::env::var(b"HOME").map(|h| String::from(slate_rt::lossy(&h))).unwrap_or_default();
    [
        format!("{home}/.local/share/flatpak/exports/share/applications"),
        String::from("/var/lib/slate/linux/var/lib/flatpak/exports/share/applications"),
    ]
}

/// A Flatpak app's name and icon, by its ID (what slate-linux-app calls
/// its window): from its exported entry, if it is installed.
pub fn flatpak_app(id: &str) -> Option<(String, Option<Rc<Image>>)> {
    let ok = id.split('.').count() >= 3
        && id.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'));
    if !ok {
        return None;
    }
    export_dirs().into_iter().find_map(|dir| {
        let text = fs::read_file(format!("{dir}/{id}.desktop").as_bytes()).ok()?;
        let a = crate::launcher::parse_desktop_entry(&slate_rt::lossy(&text))?;
        let image = resolve(&dir, &a.icon_name).or_else(|| from_catalog(id)).and_then(|p| load(&p));
        Some((a.name, image))
    })
}

/// Draw `img` into `a` (logical pixels), scaled to fit, its transparency
/// kept.
pub fn draw(p: &mut Painter<'_>, img: &Image, a: Area) {
    let d = p.device(&a);
    if d.w <= 0 || d.h <= 0 || img.width == 0 || img.height == 0 {
        return;
    }
    let side = d.w.min(d.h) as u32;
    let s = img.scaled(side, side);
    let (x, y) = (d.x + (d.w - side as i32) / 2, d.y + (d.h - side as i32) / 2);
    p.canvas.draw_image(x, y, side as i32, side as i32, &s.pixels);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn found_beside_the_entries() {
        let dir = std::env::temp_dir().join(format!("strata-icons-{}", std::process::id()));
        let share = dir.join("exports/share");
        std::fs::create_dir_all(share.join("applications")).unwrap();
        std::fs::create_dir_all(share.join("icons/hicolor/128x128/apps")).unwrap();
        std::fs::create_dir_all(share.join("icons/hicolor/48x48/apps")).unwrap();
        std::fs::write(share.join("icons/hicolor/128x128/apps/org.example.App.png"), b"x").unwrap();
        std::fs::write(share.join("icons/hicolor/48x48/apps/org.example.App.png"), b"x").unwrap();
        let apps = share.join("applications");
        let apps = apps.to_str().unwrap();
        // 64 isn't there; 128 comes before 48.
        let got = resolve(apps, "org.example.App").unwrap();
        assert!(got.ends_with("/icons/hicolor/128x128/apps/org.example.App.png"), "{got}");
        assert_eq!(resolve(apps, "org.other.App"), None);
        assert_eq!(resolve(apps, "../../etc/passwd"), None);
        assert_eq!(resolve("/x/y", "org.example.App"), None);
        // Not a PNG: not loaded.
        assert!(load(&got).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn drawn_scaled_with_its_transparency() {
        let mut c = slate_ui::Canvas::new(20, 20, slate_ui::Color::rgb(0x102030));
        let img = Image { width: 4, height: 4, pixels: alloc::vec![0xFFFF_0000; 16] };
        let mut hole = img.clone();
        hole.pixels[0] = 0;
        let mut cache = slate_ui::text::GlyphCache::default();
        {
            let mut p = Painter::new(&mut c, &mut cache, 1.0);
            draw(&mut p, &hole, Area::new(2.0, 2.0, 8.0, 8.0));
        }
        assert_eq!(c.pixel(9, 9), 0xFFFF_0000);
        assert_eq!(c.pixel(2, 2), 0xFF10_2030, "the transparent corner shows what was under it");
        assert_eq!(c.pixel(11, 11), 0xFF10_2030, "nothing outside");
    }
}
