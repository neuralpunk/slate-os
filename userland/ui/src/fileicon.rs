// SPDX-License-Identifier: MIT OR Apache-2.0

//! File icons: filled, two-tone pictures of folders and files for the
//! places they are shown large (the desktop, Files' grid), where the line
//! icons look thin. A folder is a back panel with a tab and a lighter
//! front; a file is a page with its corner folded, what is on it saying
//! what it is (lines of text, a landscape, a zip, a prompt), and a badge
//! with its extension. Monochrome, in graphite's chalk and near-black
//! (docs/design/STRATA_COLORS.md: a file's type is no meaning that takes a
//! colour); drawn in a 48-unit box, in logical pixels.

use alloc::string::String;

use crate::color::Color;
use crate::graphite::{Palette, mix};
use crate::paint::Painter;
use crate::path::Path;
use crate::shadow::BoxShadow;
use crate::text::Face;
use crate::ui::Area;

/// What an icon shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Folder,
    Text,
    Picture,
    Archive,
    /// A program (a file that runs).
    Program,
    /// Anything else: a blank page.
    Other,
}

/// The extensions of each kind (lower case).
const PICTURES: [&str; 10] = ["png", "jpg", "jpeg", "gif", "bmp", "ppm", "pgm", "qoi", "webp", "svg"];
const ARCHIVES: [&str; 10] = ["zip", "tar", "gz", "tgz", "xz", "bz2", "zst", "7z", "qpk", "rar"];
/// Text, and documents whose pages are mostly text.
const TEXTS: [&str; 35] = [
    "txt", "md", "rst", "log", "csv", "tsv", "json", "toml", "yaml", "yml", "ini", "conf", "cfg", "xml", "html", "css",
    "js", "rs", "c", "h", "py", "sh", "ics", "vcf", "odt", "ods", "odp", "pdf", "doc", "docx", "xls", "xlsx", "rtf",
    "epub", "tex",
];

fn extension(name: &str) -> Option<String> {
    let (stem, ext) = name.rsplit_once('.')?;
    (!stem.is_empty() && !ext.is_empty() && ext.len() <= 4 && ext.chars().all(|c| c.is_ascii_alphanumeric()))
        .then(|| ext.to_ascii_lowercase())
}

/// The kind of a file called `name` (a folder is the caller's to know).
pub fn kind_of(name: &str, executable: bool) -> Kind {
    match extension(name) {
        Some(e) if PICTURES.contains(&e.as_str()) => Kind::Picture,
        Some(e) if ARCHIVES.contains(&e.as_str()) => Kind::Archive,
        Some(e) if TEXTS.contains(&e.as_str()) => Kind::Text,
        _ if executable => Kind::Program,
        // README, NOTES...: text more often than not.
        None => Kind::Text,
        Some(_) => Kind::Other,
    }
}

/// The badge a file called `name` gets: its extension in capitals.
pub fn badge_of(name: &str) -> Option<String> {
    extension(name).map(|e| e.to_ascii_uppercase())
}

/// The tones, from the palette: light objects on graphite, mid greys on
/// the light variant.
struct Tones {
    paper: Color,
    edge: Color,
    fold: Color,
    ink: Color,
    back: Color,
    front: Color,
    lip: Color,
    badge: Color,
    badge_text: Color,
    shadow: Color,
}

fn tones(pal: &Palette) -> Tones {
    let w = pal.window;
    let light = {
        let c = w.0;
        ((c >> 16) & 0xFF) + ((c >> 8) & 0xFF) + (c & 0xFF) > 3 * 128
    };
    if light {
        let t = pal.text_1;
        Tones {
            paper: Color::rgb(0xFDFCFB),
            edge: mix(t, w, 0.68),
            fold: mix(t, w, 0.84),
            ink: mix(t, w, 0.58),
            back: mix(t, w, 0.58),
            front: mix(t, w, 0.72),
            lip: mix(t, w, 0.86),
            badge: mix(t, w, 0.12),
            badge_text: w,
            shadow: Color::rgb(0).with_alpha(36),
        }
    } else {
        let t = pal.chalk;
        Tones {
            paper: mix(t, w, 0.04),
            edge: mix(t, w, 0.42),
            fold: mix(t, w, 0.26),
            ink: mix(t, w, 0.60),
            back: mix(t, w, 0.58),
            front: mix(t, w, 0.20),
            lip: mix(t, w, 0.04),
            badge: mix(w, t, 0.06),
            badge_text: pal.text_1,
            shadow: Color::rgb(0).with_alpha(110),
        }
    }
}

/// A page from (x0, y0) to (x1, y1) with its top right corner folded
/// `fold` in, the other corners rounded `r`.
fn page(x0: f32, y0: f32, x1: f32, y1: f32, fold: f32, r: f32) -> Path {
    let mut p = Path::new();
    p.move_to(x0 + r, y0)
        .line_to(x1 - fold, y0)
        .line_to(x1, y0 + fold)
        .line_to(x1, y1 - r)
        .quad_to(x1, y1, x1 - r, y1)
        .line_to(x0 + r, y1)
        .quad_to(x0, y1, x0, y1 - r)
        .line_to(x0, y0 + r)
        .quad_to(x0, y0, x0 + r, y0)
        .close();
    p
}

/// Draw `kind`'s icon in the `size`-wide square at (x, y); `badge` (a
/// typeface and the text) marks a file's type, when there is room.
pub fn draw(
    p: &mut Painter<'_>,
    pal: &Palette,
    kind: Kind,
    x: f32,
    y: f32,
    size: f32,
    badge: Option<(&Face<'_>, &str)>,
) {
    let k = size / 48.0;
    let u = |v: f32| v * k;
    let tn = tones(pal);
    let soft = BoxShadow { dx: 0.0, dy: u(1.5), blur: u(5.0), spread: 0.0, color: tn.shadow };
    if kind == Kind::Folder {
        // The back panel and its tab, then the front, a little lower.
        let (l, r) = (x + u(4.0), x + u(44.0));
        let mut back = Path::new();
        let rr = u(3.0);
        back.move_to(l + rr, y + u(7.0))
            .line_to(x + u(17.5), y + u(7.0))
            .line_to(x + u(21.5), y + u(11.0))
            .line_to(r - rr, y + u(11.0))
            .quad_to(r, y + u(11.0), r, y + u(11.0) + rr)
            .line_to(r, y + u(38.0))
            .line_to(l, y + u(38.0))
            .line_to(l, y + u(7.0) + rr)
            .quad_to(l, y + u(7.0), l + rr, y + u(7.0))
            .close();
        let front = Area::new(l, y + u(16.0), u(40.0), u(26.0));
        p.shadow(front, rr, &soft);
        p.path(&back, tn.back);
        p.fill(front, rr, tn.front);
        // The light catching its top edge.
        p.fill(Area::new(front.x + rr, front.y, front.w - 2.0 * rr, u(1.0).max(1.0)), 0.0, tn.lip);
        return;
    }
    let (x0, y0, x1, y1) = (x + u(9.0), y + u(4.0), x + u(39.0), y + u(44.0));
    let (fold, r) = (u(10.0), u(3.0));
    p.shadow(Area::new(x0, y0, x1 - x0, y1 - y0), r, &soft);
    p.path(&page(x0, y0, x1, y1, fold, r), tn.edge);
    let i = 1.0;
    p.path(&page(x0 + i, y0 + i, x1 - i, y1 - i, fold - 0.4 * i, (r - i).max(0.5)), tn.paper);
    // The folded corner.
    let mut corner = Path::new();
    corner
        .move_to(x1 - fold, y0)
        .line_to(x1 - fold, y0 + fold - u(1.5))
        .quad_to(x1 - fold, y0 + fold, x1 - fold + u(1.5), y0 + fold)
        .line_to(x1, y0 + fold)
        .close();
    p.path(&corner, tn.fold);
    p.polyline(&[(x1 - fold, y0), (x1, y0 + fold)], 1.0, tn.edge);
    let line = |p: &mut Painter<'_>, a: f32, b: f32, at: f32| {
        p.polyline(&[(x + u(a), y + u(at)), (x + u(b), y + u(at))], u(1.6).max(1.0), tn.ink);
    };
    match kind {
        Kind::Text => {
            line(p, 14.0, 25.0, 12.0);
            for (n, end) in [34.0, 34.0, 29.0, 34.0, 26.0].into_iter().enumerate() {
                line(p, 14.0, end, 18.0 + n as f32 * 4.5);
            }
        }
        Kind::Picture => {
            let frame = Area::new(x + u(13.0), y + u(16.0), u(22.0), u(17.0));
            p.fill(frame, u(1.5), tn.ink);
            let mut hills = Path::new();
            hills
                .move_to(frame.x, frame.bottom())
                .line_to(frame.x, frame.bottom() - u(3.0))
                .line_to(x + u(20.0), y + u(24.5))
                .line_to(x + u(25.0), y + u(29.0))
                .line_to(x + u(28.5), y + u(26.0))
                .line_to(frame.right(), y + u(30.5))
                .line_to(frame.right(), frame.bottom())
                .close();
            p.path(&hills, tn.paper.with_alpha(150));
            p.path(&Path::circle(x + u(29.5), y + u(20.5), u(2.2)), tn.paper);
        }
        Kind::Archive => {
            // The zip down the middle, then its pull.
            for n in 0..5 {
                let left = n % 2 == 0;
                let bx = if left { x + u(21.0) } else { x + u(24.0) };
                p.fill(Area::new(bx, y0 + u(1.5 + n as f32 * 3.5), u(3.0), u(2.5)), 0.0, tn.ink);
            }
            let pull = Area::new(x + u(20.5), y + u(21.5), u(7.0), u(8.0));
            p.fill(pull, u(1.5), tn.ink);
            p.fill(Area::new(pull.x + u(2.0), pull.y + u(4.0), u(3.0), u(2.5)), u(0.8), tn.paper);
        }
        Kind::Program => {
            let w = u(2.0).max(1.2);
            p.polyline(
                &[(x + u(15.0), y + u(19.0)), (x + u(20.5), y + u(23.5)), (x + u(15.0), y + u(28.0))],
                w,
                tn.ink,
            );
            p.polyline(&[(x + u(23.0), y + u(28.0)), (x + u(31.0), y + u(28.0))], w, tn.ink);
        }
        Kind::Folder | Kind::Other => {}
    }
    // The badge, over the page's lower left, when it fits and reads.
    if let Some((face, text)) = badge.filter(|_| size >= 32.0)
        && !text.is_empty()
    {
        let st = p.style(face, u(8.5), tn.badge_text);
        let tw = p.measure(&st, text);
        let h = u(11.0);
        let a = Area::new(x + u(5.0), y + u(31.0), tw + u(7.0), h);
        p.fill(a, u(2.5), tn.badge);
        p.line(&st, a.x + u(3.5), a.y, h, text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_and_badges() {
        assert_eq!(kind_of("beach.PNG", false), Kind::Picture);
        assert_eq!(kind_of("src.tar.gz", false), Kind::Archive);
        assert_eq!(kind_of("notes.txt", false), Kind::Text);
        assert_eq!(kind_of("README", false), Kind::Text);
        assert_eq!(kind_of("run", true), Kind::Program);
        assert_eq!(kind_of("disk.img", false), Kind::Other);
        assert_eq!(kind_of(".profile", false), Kind::Text);
        assert_eq!(badge_of("beach.png").as_deref(), Some("PNG"));
        assert_eq!(badge_of("README"), None);
        assert_eq!(badge_of("a.verylong"), None);
        assert_eq!(badge_of(".hidden"), None);
    }
}
