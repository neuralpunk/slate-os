// SPDX-License-Identifier: MIT OR Apache-2.0

//! Notifications (ADR 0186): what apps say through Strata's protocol
//! (`Notify`), `strata-notify` and, for Linux apps, slate-portal's
//! `org.freedesktop.Notifications`, and what Strata says itself (the
//! Clock's alarms). Each shows as a banner at the top right for a few
//! seconds (an urgent one until dismissed), then waits in quick
//! settings' list until cleared. Do Not Disturb keeps the banners away,
//! but for urgent ones.

use alloc::string::String;
use alloc::vec::Vec;

use slate_ui::graphite::Palette;
use slate_ui::icon::Icon;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;
use strata_proto::urgency;

use crate::draw;
use crate::fonts::Fonts;

/// How long a banner shows (ms).
pub const BANNER_MS: i64 = 5000;
/// How many notifications are kept.
pub const KEPT: usize = 50;
/// How many banners show at once.
pub const BANNERS: usize = 3;
/// A banner's width, and its distance from the screen's right edge.
pub const BANNER_W: f32 = 360.0;
const EDGE: f32 = 8.0;
/// How long a banner takes to slide in (ms).
const SLIDE_MS: i64 = 160;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub id: u32,
    /// The client that sent it (0: Strata's own).
    pub pid: i32,
    /// The app's own number for it (0: none).
    pub key: u32,
    pub app: String,
    pub summary: String,
    pub body: String,
    pub urgency: u8,
    /// When it came (ms), and the time of day then ("14:32").
    pub at: i64,
    pub clock: String,
    /// Its banner shows until then (ms); None once gone.
    pub banner_until: Option<i64>,
    pub read: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Notes {
    /// Oldest first.
    pub list: Vec<Note>,
    next: u32,
    /// Do Not Disturb.
    pub quiet: bool,
}

impl Notes {
    /// A notification came: its id. One with the same sender and key
    /// (not 0) is replaced.
    #[allow(clippy::too_many_arguments)]
    pub fn add(
        &mut self,
        pid: i32,
        key: u32,
        app: &str,
        summary: &str,
        body: &str,
        urgency: u8,
        now: i64,
        clock: &str,
    ) -> u32 {
        if key != 0 {
            self.list.retain(|n| !(n.pid == pid && n.key == key));
        }
        self.next += 1;
        let banner_until = match urgency {
            urgency::CRITICAL => Some(i64::MAX),
            _ if self.quiet => None,
            _ => Some(now + BANNER_MS),
        };
        self.list.push(Note {
            id: self.next,
            pid,
            key,
            app: String::from(if app.is_empty() { "An app" } else { app }),
            summary: String::from(summary),
            body: String::from(body),
            urgency,
            at: now,
            clock: String::from(clock),
            banner_until,
            read: false,
        });
        if self.list.len() > KEPT {
            self.list.remove(0);
        }
        self.next
    }

    /// The sender's notification `key` is no longer wanted.
    pub fn remove_key(&mut self, pid: i32, key: u32) -> bool {
        let n = self.list.len();
        self.list.retain(|x| !(x.pid == pid && x.key == key));
        n != self.list.len()
    }

    /// Notification `id` dismissed: its banner goes; it stays listed.
    pub fn dismiss(&mut self, id: u32) {
        if let Some(n) = self.list.iter_mut().find(|n| n.id == id) {
            n.banner_until = None;
            n.read = true;
        }
    }

    pub fn clear(&mut self) {
        self.list.clear();
    }

    /// Seen in the list: none unread.
    pub fn mark_read(&mut self) {
        for n in &mut self.list {
            n.read = true;
        }
    }

    pub fn unread(&self) -> bool {
        self.list.iter().any(|n| !n.read)
    }

    /// The banners showing at `now`, newest first.
    pub fn banners(&self, now: i64) -> Vec<&Note> {
        self.list.iter().rev().filter(|n| n.banner_until.is_some_and(|t| now < t)).take(BANNERS).collect()
    }

    /// Banners whose time ran out go; true if any did.
    pub fn expire(&mut self, now: i64) -> bool {
        let mut gone = false;
        for n in &mut self.list {
            if n.banner_until.is_some_and(|t| now >= t) {
                n.banner_until = None;
                gone = true;
            }
        }
        gone
    }

    /// Whether a banner is still sliding in at `now`.
    pub fn sliding(&self, now: i64) -> bool {
        self.banners(now).iter().any(|n| now - n.at < SLIDE_MS)
    }

    /// The newest `n`, for quick settings' list.
    pub fn newest(&self, n: usize) -> Vec<Listed> {
        self.list
            .iter()
            .rev()
            .take(n)
            .map(|x| Listed { app: x.app.clone(), summary: x.summary.clone(), clock: x.clock.clone() })
            .collect()
    }
}

/// A notification as quick settings lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    pub app: String,
    pub summary: String,
    pub clock: String,
}

/// Where a banner was drawn: its notification, the banner, its close
/// button.
pub type BannerHit = (u32, Area, Area);

/// A banner's lines of body text (at most two) in `w`.
fn body_lines(p: &Painter<'_>, f: &Fonts<'_>, pal: &Palette, body: &str, w: f32) -> Vec<String> {
    if body.is_empty() {
        return Vec::new();
    }
    let st = p.style(&f.regular, 12.5, pal.text_3);
    let mut lines = slate_ui::text::wrap(&st, body, w * p.scale);
    if lines.len() > 2 {
        lines.truncate(2);
        let last = lines.pop().unwrap_or_default();
        lines.push(draw::truncate_end(p, &st, &alloc::format!("{last}…"), w));
    }
    lines
}

/// Draw the banners at the top right of a screen `w` wide, under a top
/// bar `bar_h` tall; where each is.
pub fn draw_banners(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    notes: &Notes,
    w: f32,
    now: i64,
    reduced: bool,
) -> Vec<BannerHit> {
    let mut hits = Vec::new();
    let mut y = pal.shape.bar_h + EDGE;
    let inner = BANNER_W - 2.0 * 16.0 - 24.0;
    for n in notes.banners(now) {
        let lines = body_lines(p, f, pal, &n.body, inner);
        let h = 56.0 + 18.0 * lines.len() as f32;
        // Sliding in from the right, fading in.
        let t = if reduced { 1.0 } else { ((now - n.at) as f32 / SLIDE_MS as f32).clamp(0.0, 1.0) };
        let k = crate::motion::ease_out(t);
        let a = Area::new(w - EDGE - BANNER_W + (1.0 - k) * 24.0, y, BANNER_W, h);
        p.shadow_under(a, 12.0, &draw::MENU);
        p.fill(a, 12.0, pal.overlay.faded(k));
        draw::rim(p, pal, a, 12.0);
        if n.urgency == urgency::CRITICAL {
            // Urgent: ochre's border (STRATA_COLORS: a warning).
            p.border(a, 12.0, 1.0, pal.accents.ochre.border.faded(k));
        }
        let small = p.style(&f.regular, 11.5, pal.muted.faded(k));
        p.line(&small, a.x + 16.0, a.y + 10.0, 16.0, &alloc::format!("{} · {}", n.app, n.clock));
        let title = p.style(&f.medium, 13.5, pal.text_1.faded(k));
        let summary = draw::truncate_end(p, &title, &n.summary, inner);
        p.line(&title, a.x + 16.0, a.y + 28.0, 20.0, &summary);
        let body = p.style(&f.regular, 12.5, pal.text_3.faded(k));
        for (i, l) in lines.iter().enumerate() {
            p.line(&body, a.x + 16.0, a.y + 48.0 + 18.0 * i as f32, 18.0, l);
        }
        let close = Area::new(a.right() - 32.0, a.y + 8.0, 24.0, 24.0);
        p.icon(Icon::Close, close.x + 6.0, close.y + 6.0, 12.0, pal.muted.faded(k));
        hits.push((n.id, a, close));
        y += h + 8.0;
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banners_come_and_go() {
        let mut n = Notes::default();
        let a = n.add(7, 0, "Files", "Copied", "3 files", urgency::NORMAL, 1000, "10:00");
        assert_eq!(n.banners(1001).len(), 1);
        assert!(n.unread());
        assert!(!n.expire(1000 + BANNER_MS - 1));
        assert!(n.expire(1000 + BANNER_MS));
        assert!(n.banners(1000 + BANNER_MS).is_empty());
        // Still listed.
        assert_eq!(n.newest(5).len(), 1);
        // An urgent one stays; dismissing it ends its banner.
        let b = n.add(0, 0, "Clock", "Alarm", "07:30", urgency::CRITICAL, 2000, "07:30");
        assert_eq!(n.banners(1_000_000).len(), 1);
        n.dismiss(b);
        assert!(n.banners(2001).is_empty());
        assert_ne!(a, b);
        n.mark_read();
        assert!(!n.unread());
    }

    #[test]
    fn keys_replace_and_quiet_holds_banners() {
        let mut n = Notes::default();
        n.add(7, 4, "Firefox", "Download", "50%", urgency::NORMAL, 0, "10:00");
        n.add(7, 4, "Firefox", "Download", "done", urgency::NORMAL, 10, "10:00");
        n.add(8, 4, "Other", "x", "", urgency::NORMAL, 10, "10:00");
        assert_eq!(n.list.len(), 2);
        assert_eq!(n.list[0].body, "done");
        assert!(n.remove_key(7, 4));
        assert_eq!(n.list.len(), 1);
        n.quiet = true;
        n.add(1, 0, "A", "b", "", urgency::NORMAL, 20, "10:00");
        assert_eq!(n.list.last().unwrap().banner_until, None);
        n.add(1, 0, "A", "urgent", "", urgency::CRITICAL, 20, "10:00");
        assert_eq!(n.list.last().unwrap().banner_until, Some(i64::MAX));
        // No more than KEPT; at most BANNERS at once.
        n.quiet = false;
        for i in 0..60 {
            n.add(1, 0, "A", "b", "", urgency::NORMAL, 30 + i, "10:00");
        }
        assert_eq!(n.list.len(), KEPT);
        assert_eq!(n.banners(100).len(), BANNERS);
    }
}
