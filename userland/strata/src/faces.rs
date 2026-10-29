// SPDX-License-Identifier: MIT OR Apache-2.0

//! Account pictures and picture wallpapers (ADR 0110's second addendum).
//!
//! A person's picture is `/var/lib/slate/faces/LOGIN.png`, 128 × 128,
//! written by Settings as that person. The folder is sticky and open to
//! all, as /tmp is (the broker makes it at start), because homes are
//! private and the login screen runs as no one in particular. A reader
//! believes a picture only if it is a plain file (not a link) owned by
//! the account it is named after: anyone can put a file there, but only
//! under their own name.
//!
//! A wallpaper of one's own is a copy of the picture chosen, in
//! `~/.config/strata/wallpaper`, drawn to cover the screen.

use alloc::string::String;
use alloc::vec::Vec;

use slate_image::Image;
use slate_rt::fs;

/// Where the pictures are.
pub const DIR: &str = "/var/lib/slate/faces";
/// A picture's side, in pixels.
pub const SIDE: u32 = 128;
/// The most a picture file may be (bytes).
const FACE_MAX: i64 = 256 << 10;
/// The most a picture chosen for a wallpaper or an account may be.
pub const PICTURE_MAX: i64 = 32 << 20;

/// `img` cut to the shape of `w` × `h` around its middle, then scaled to
/// it: it covers the area, as a wallpaper does.
pub fn cover(img: &Image, w: u32, h: u32) -> Image {
    let (iw, ih) = (img.width.max(1) as u64, img.height.max(1) as u64);
    // The largest part with w:h's shape.
    let (cw, ch) = if iw * h as u64 > ih * w as u64 {
        ((ih * w as u64 / h.max(1) as u64).max(1), ih)
    } else {
        (iw, (iw * h as u64 / w.max(1) as u64).max(1))
    };
    let (x0, y0) = ((iw - cw) / 2, (ih - ch) / 2);
    let mut pixels = Vec::with_capacity((cw * ch) as usize);
    for y in y0..y0 + ch {
        let row = (y * iw) as usize;
        pixels.extend_from_slice(&img.pixels[row + x0 as usize..row + (x0 + cw) as usize]);
    }
    Image { width: cw as u32, height: ch as u32, pixels }.scaled(w, h)
}

fn path(login: &str) -> String {
    alloc::format!("{DIR}/{login}.png")
}

/// `login`'s picture, if there is one that `uid` owns.
pub fn load(login: &str, uid: u32) -> Option<Image> {
    let fd = fs::open(path(login).as_bytes(), fs::O_RDONLY | fs::O_NOFOLLOW | fs::O_CLOEXEC, 0).ok()?;
    let st = fs::fstat(fd).ok();
    let ok = st.is_some_and(|s| s.mode & fs::S_IFMT == fs::S_IFREG && s.uid == uid && s.size <= FACE_MAX);
    let mut data = Vec::new();
    if ok {
        let mut buf = [0u8; 16384];
        while let Ok(n) = slate_rt::io::read(fd, &mut buf) {
            if n == 0 || data.len() + n > FACE_MAX as usize {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
    }
    let _ = slate_rt::io::close(fd);
    let img = slate_image::decode(&data).ok()?;
    Some(if (img.width, img.height) == (SIDE, SIDE) { img } else { cover(&img, SIDE, SIDE) })
}

/// A picture file's image, if it is one Slate reads and not too large.
pub fn read_picture(file: &str) -> Result<Image, String> {
    let st = fs::stat(file.as_bytes()).map_err(|e| alloc::format!("{file}: {e}"))?;
    if st.mode & fs::S_IFMT != fs::S_IFREG {
        return Err(alloc::format!("{file} is not a file"));
    }
    if st.size > PICTURE_MAX {
        return Err(String::from("That picture is over 32 MiB."));
    }
    let data = fs::read_file(file.as_bytes()).map_err(|e| alloc::format!("{file}: {e}"))?;
    slate_image::decode(&data).map_err(|_| String::from("That isn't a picture Slate can read (PNG, JPEG, GIF or BMP)."))
}

/// The PNG of `img` cut and scaled to [`SIDE`].
pub fn face_png(img: &Image) -> Vec<u8> {
    let f = cover(img, SIDE, SIDE);
    let mut c = slate_ui::Canvas::new(SIDE as i32, SIDE as i32, slate_ui::Color::rgb(0));
    c.pixels.copy_from_slice(&f.pixels);
    slate_ui::png::encode(&c)
}

/// Make `img` the picture of `login` (the person running this): a new
/// file put in place whole. A file someone else left under the name is
/// in the way (the folder is sticky).
pub fn save(login: &str, img: &Image) -> Result<(), String> {
    let png = face_png(img);
    let tmp = alloc::format!("{DIR}/.{login}.{}.new", slate_rt::process::getpid());
    let fd = fs::open(tmp.as_bytes(), fs::O_WRONLY | fs::O_CREAT | fs::O_EXCL | fs::O_NOFOLLOW | fs::O_CLOEXEC, 0o644)
        .map_err(|e| alloc::format!("{DIR}: {e}"))?;
    let w = slate_rt::io::write_all(fd, &png);
    let _ = slate_rt::io::close(fd);
    if let Err(e) = w {
        let _ = fs::unlink(tmp.as_bytes());
        return Err(alloc::format!("{e}"));
    }
    let _ = fs::chmod(tmp.as_bytes(), 0o644);
    fs::rename(tmp.as_bytes(), path(login).as_bytes()).map_err(|e| {
        let _ = fs::unlink(tmp.as_bytes());
        alloc::format!("Couldn't put the picture in place: {e}")
    })
}

/// Whether a file someone other than `uid` owns sits where `login`'s
/// picture goes (the folder is sticky: only the broker can take it away).
pub fn blocked(login: &str, uid: u32) -> bool {
    fs::lstat(path(login).as_bytes()).is_ok_and(|s| s.uid != uid)
}

/// Remove `login`'s picture (the initials come back).
pub fn remove(login: &str) -> Result<(), String> {
    match fs::unlink(path(login).as_bytes()) {
        Ok(()) | Err(slate_rt::Errno::ENOENT) => Ok(()),
        Err(e) => Err(alloc::format!("{e}")),
    }
}

/// `~/.config/strata/wallpaper`: a wallpaper of one's own.
pub fn wallpaper_path() -> Option<Vec<u8>> {
    let home = slate_rt::env::var(b"HOME").filter(|h| !h.is_empty())?;
    Some(fs::join(&home, b".config/strata/wallpaper"))
}

/// The person's own wallpaper picture, if there is one Slate reads.
pub fn wallpaper() -> Option<Image> {
    let p = wallpaper_path()?;
    let st = fs::stat(&p).ok()?;
    if st.size > PICTURE_MAX {
        return None;
    }
    slate_image::decode(&fs::read_file(&p).ok()?).ok()
}

/// Copy the picture `file` (checked first) to be the wallpaper.
pub fn set_wallpaper(file: &str) -> Result<(), String> {
    read_picture(file)?;
    let data = fs::read_file(file.as_bytes()).map_err(|e| alloc::format!("{e}"))?;
    let p = wallpaper_path().ok_or("HOME is not set")?;
    let home = slate_rt::env::var(b"HOME").unwrap_or_default();
    for d in [fs::join(&home, b".config"), fs::join(&home, b".config/strata")] {
        let _ = fs::mkdir(&d, 0o755);
    }
    let mut tmp = p.clone();
    tmp.extend_from_slice(b".new");
    fs::write_file(&tmp, &data, 0o644).map_err(|e| alloc::format!("{e}"))?;
    fs::rename(&tmp, &p).map_err(|e| alloc::format!("{e}"))
}

/// Draw `img` into `a` (logical pixels) with corners of radius `r`,
/// covering it: the tile of a person.
pub fn draw(p: &mut slate_ui::paint::Painter<'_>, img: &Image, a: slate_ui::ui::Area, r: f32) {
    let d = p.device(&a);
    if d.w <= 0 || d.h <= 0 {
        return;
    }
    let im = cover(img, d.w as u32, d.h as u32);
    let rr = r * p.scale;
    let clip = p.canvas.clip();
    let (cw, ch) = (p.canvas.width, p.canvas.height);
    for y in 0..d.h {
        for x in 0..d.w {
            let (px, py) = (d.x + x, d.y + y);
            if px < 0 || py < 0 || px >= cw || py >= ch || !clip.contains(px, py) {
                continue;
            }
            // Coverage at the rounded corners.
            let (fx, fy) = (x as f32 + 0.5, y as f32 + 0.5);
            let cx = if fx < rr {
                rr - fx
            } else if fx > d.w as f32 - rr {
                fx - (d.w as f32 - rr)
            } else {
                0.0
            };
            let cy = if fy < rr {
                rr - fy
            } else if fy > d.h as f32 - rr {
                fy - (d.h as f32 - rr)
            } else {
                0.0
            };
            let cover = if cx > 0.0 && cy > 0.0 {
                (rr - slate_ui::math::sqrt(cx * cx + cy * cy) + 0.5).clamp(0.0, 1.0)
            } else {
                1.0
            };
            let src = im.pixels[(y * d.w + x) as usize];
            let alpha = ((src >> 24) & 0xFF) as f32 / 255.0 * cover;
            if alpha <= 0.0 {
                continue;
            }
            let i = (py * cw + px) as usize;
            let dst = p.canvas.pixels[i];
            let mix = |sh: u32| {
                let (s, t) = (((src >> sh) & 0xFF) as f32, ((dst >> sh) & 0xFF) as f32);
                ((s * alpha + t * (1.0 - alpha)) as u32 & 0xFF) << sh
            };
            p.canvas.pixels[i] = 0xFF00_0000 | mix(16) | mix(8) | mix(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covering() {
        // 4 × 2, left half red, right half blue: the square is the middle.
        let red = 0xFFFF_0000;
        let blue = 0xFF00_00FF;
        let img = Image { width: 4, height: 2, pixels: std::vec![red, red, blue, blue, red, red, blue, blue] };
        let sq = cover(&img, 2, 2);
        assert_eq!(sq.pixels, [red, blue, red, blue]);
        let tall = cover(&img, 1, 2);
        assert_eq!((tall.width, tall.height), (1, 2));
        // A face is 128 square, as a PNG Slate reads back.
        let png = face_png(&img);
        let back = slate_image::decode(&png).unwrap();
        assert_eq!((back.width, back.height), (SIDE, SIDE));
    }
}
