// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate's line icons, drawn as strokes in a 24-unit box (the convention
//! of common line-icon sets; these are Slate's own drawings): the
//! installer's (close, chevron, globe, accessibility, check, warning) and
//! Strata's (shield, split pane, network, battery, search, folder, letter,
//! undo, terminal, power, key hints, and the window buttons).

use crate::canvas::Canvas;
use crate::color::Color;
use crate::path::{Path, Transform};
use crate::stroke::polyline;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    Close,
    ChevronDown,
    Globe,
    Accessibility,
    Check,
    Warning,
    /// Slate mode (Strata's domain indicator).
    Shield,
    /// The Linux domain.
    SplitPane,
    Wifi,
    /// An empty battery; [`battery`] draws its charge.
    Battery,
    Search,
    Folder,
    Letter,
    Undo,
    Terminal,
    Power,
    /// The Enter key (↵), for key hints.
    Enter,
    /// The arrow keys (↑↓, ←→), for key hints.
    UpDown,
    LeftRight,
    /// A window's minimise, maximise and restore buttons.
    Minimize,
    Maximize,
    Restore,
    /// Settings: three sliders.
    Sliders,
    /// Back.
    ChevronLeft,
    /// The backspace key: a tag pointing left with a cross in it.
    Backspace,
    /// Apps (M28): a calculator, a clock face, and help (an i in a ring).
    Calculator,
    Clock,
    Info,
    /// A picture: a frame with a hill and a sun.
    Picture,
    /// An archive: a box with a lid and a zip down its middle.
    Archive,
    /// Forward.
    ChevronRight,
    /// Files' places: a house, a disk, the trash.
    Home,
    Disk,
    Trash,
    /// A calendar page, and a person (contacts).
    Calendar,
    Person,
    /// The Applications menu's categories (ADR 0110): every app (a grid),
    /// office (a briefcase), development (angle brackets), sound and
    /// video (a play button).
    Grid,
    Briefcase,
    Code,
    Play,
    /// The power dialog (ADR 0110): a padlock, restart (a circling
    /// arrow), log out (a door with an arrow leaving it).
    Lock,
    Restart,
    LogOut,
    /// Settings' accounts: two people.
    People,
    /// The System Monitor: a pulse across a line (ADR 0112).
    Activity,
    /// The Software Updater: an arrow down into a tray.
    Download,
    /// Bluetooth's rune (ADR 0113).
    Bluetooth,
    /// A page with a folded corner and two lines (ADR 0124): the Text
    /// Editor.
    Document,
    /// A window: a frame with its title bar (ADR 0124's addendum), the
    /// glyph of a window whose program is no app entry's.
    Window,
    /// A display: a screen on a stand (Settings › Displays, ADR 0170).
    Display,
    /// Games (ADR 0177): two cards, a diamond on the front one
    /// (Solitaire); a flag on its pole (Mines).
    Cards,
    Flag,
    /// A speaker with two sound waves (Settings › Sound, ADR 0184).
    Speaker,
    /// The speaker, crossed out: muted (ADR 0186).
    SpeakerMuted,
    /// The sun: brightness.
    Sun,
    /// A crescent moon: dark style, Night Light.
    Moon,
    /// A mouse: the pointer's settings.
    Mouse,
    /// A bell: notifications.
    Bell,
    /// The bell struck through: Do Not Disturb.
    BellOff,
}

/// Draw `icon` `size` device pixels square at (x, y).
pub fn draw(canvas: &mut Canvas, icon: Icon, x: f32, y: f32, size: f32, color: Color) {
    let t = Transform::new(size / 24.0, x, y);
    // Strokes are 1.75 units wide; at small sizes keep them visible.
    let w = if size < 16.0 { 2.2 } else { 1.75 };
    let mut p = Path::new();
    match icon {
        Icon::Close => {
            p.extend(&polyline(&[(6.0, 6.0), (18.0, 18.0)], w));
            p.extend(&polyline(&[(18.0, 6.0), (6.0, 18.0)], w));
        }
        Icon::ChevronDown => {
            p.extend(&polyline(&[(6.0, 9.0), (12.0, 15.0), (18.0, 9.0)], w));
        }
        Icon::Check => {
            p.extend(&polyline(&[(5.0, 12.5), (10.0, 17.0), (19.0, 7.0)], w * 1.3));
        }
        Icon::Globe => {
            p.extend(&ring(12.0, 12.0, 9.0, w));
            p.extend(&polyline(&[(3.0, 12.0), (21.0, 12.0)], w));
            // The meridian: an ellipse 4 wide, as two arcs of polylines.
            let mut pts = alloc::vec::Vec::new();
            for i in 0..=24 {
                let a = core::f32::consts::PI * i as f32 / 24.0;
                pts.push((12.0 + 4.2 * sin(a), 12.0 - 9.0 * cos(a)));
            }
            p.extend(&polyline(&pts, w));
            let mirrored: alloc::vec::Vec<(f32, f32)> = pts.iter().map(|&(px, py)| (24.0 - px, py)).collect();
            p.extend(&polyline(&mirrored, w));
        }
        Icon::Accessibility => {
            p.extend(&Path::circle(12.0, 4.5, 1.9));
            p.extend(&polyline(&[(5.0, 8.5), (12.0, 10.0), (19.0, 8.5)], w));
            p.extend(&polyline(&[(12.0, 10.0), (12.0, 14.5)], w));
            p.extend(&polyline(&[(8.5, 21.0), (12.0, 14.5), (15.5, 21.0)], w));
        }
        Icon::Shield => {
            let mut pts = alloc::vec![(12.0, 3.0), (19.0, 5.8), (19.0, 11.0)];
            pts.extend(cubic((19.0, 11.0), (19.0, 15.6), (16.0, 18.9), (12.0, 21.0)));
            pts.extend(cubic((12.0, 21.0), (8.0, 18.9), (5.0, 15.6), (5.0, 11.0)));
            pts.extend([(5.0, 5.8), (12.0, 3.0), (19.0, 5.8)]);
            p.extend(&polyline(&pts, w));
        }
        Icon::SplitPane => {
            p.extend(&Path::rounded_ring(3.0, 4.0, 18.0, 16.0, 2.5, w));
            p.extend(&polyline(&[(12.0, 4.5), (12.0, 19.5)], w));
        }
        Icon::Wifi => {
            for r in [13.0, 8.5, 4.0] {
                p.extend(&polyline(&arc(12.0, 19.0, r, -2.36, -0.785), w));
            }
            p.extend(&Path::circle(12.0, 19.0, 1.4));
        }
        Icon::Battery => {
            p.extend(&Path::rounded_ring(2.0, 7.0, 18.0, 10.0, 2.5, w));
            p.extend(&Path::rounded_rect(20.6, 10.0, 1.6, 4.0, 0.6));
        }
        Icon::ChevronLeft => {
            p.extend(&polyline(&[(14.5, 6.0), (8.5, 12.0), (14.5, 18.0)], w));
        }
        Icon::Calculator => {
            p.extend(&Path::rounded_ring(4.5, 2.5, 15.0, 19.0, 2.5, w));
            p.extend(&polyline(&[(8.0, 7.5), (16.0, 7.5)], w));
            for (x, y) in [(8.5, 12.5), (12.0, 12.5), (15.5, 12.5), (8.5, 17.0), (12.0, 17.0), (15.5, 17.0)] {
                p.extend(&Path::circle(x, y, 1.15));
            }
        }
        Icon::Clock => {
            p.extend(&ring(12.0, 12.0, 9.0, w));
            p.extend(&polyline(&[(12.0, 7.0), (12.0, 12.0), (15.5, 14.0)], w));
        }
        Icon::Calendar => {
            p.extend(&Path::rounded_ring(3.5, 5.0, 17.0, 15.5, 2.0, w));
            p.extend(&polyline(&[(3.5, 9.5), (20.5, 9.5)], w));
            p.extend(&polyline(&[(8.0, 3.0), (8.0, 6.5)], w));
            p.extend(&polyline(&[(16.0, 3.0), (16.0, 6.5)], w));
            for (x, y) in [(8.0, 13.5), (12.0, 13.5), (16.0, 13.5), (8.0, 17.0), (12.0, 17.0)] {
                p.extend(&Path::circle(x, y, 1.0));
            }
        }
        Icon::Person => {
            p.extend(&ring(12.0, 8.5, 3.75, w));
            p.extend(&polyline(&arc(12.0, 21.0, 7.0, core::f32::consts::PI, core::f32::consts::TAU), w));
        }
        Icon::ChevronRight => {
            p.extend(&polyline(&[(9.5, 6.0), (15.5, 12.0), (9.5, 18.0)], w));
        }
        Icon::Grid => {
            for (x, y) in [(4.0, 4.0), (13.5, 4.0), (4.0, 13.5), (13.5, 13.5)] {
                p.extend(&Path::rounded_ring(x, y, 6.5, 6.5, 1.5, w));
            }
        }
        Icon::Briefcase => {
            p.extend(&Path::rounded_ring(3.0, 7.0, 18.0, 13.0, 2.0, w));
            p.extend(&polyline(&[(9.0, 7.0), (9.0, 4.5), (15.0, 4.5), (15.0, 7.0)], w));
            p.extend(&polyline(&[(3.5, 12.5), (20.5, 12.5)], w));
        }
        Icon::Code => {
            p.extend(&polyline(&[(8.5, 7.0), (3.5, 12.0), (8.5, 17.0)], w));
            p.extend(&polyline(&[(15.5, 7.0), (20.5, 12.0), (15.5, 17.0)], w));
            p.extend(&polyline(&[(13.5, 5.0), (10.5, 19.0)], w));
        }
        Icon::Play => {
            p.extend(&ring(12.0, 12.0, 8.5, w));
            p.extend(&Path::polygon(&[(10.0, 8.5), (15.5, 12.0), (10.0, 15.5)]));
        }
        Icon::Lock => {
            p.extend(&Path::rounded_ring(5.0, 10.5, 14.0, 10.0, 2.0, w));
            p.extend(&polyline(&arc(12.0, 9.0, 4.0, core::f32::consts::PI, core::f32::consts::TAU), w));
            p.extend(&polyline(&[(8.0, 9.0), (8.0, 10.5)], w));
            p.extend(&polyline(&[(16.0, 9.0), (16.0, 10.5)], w));
            p.extend(&Path::circle(12.0, 15.5, 1.2));
        }
        Icon::Restart => {
            // Clockwise from the upper right round to the top, the head at
            // the end pointing on.
            p.extend(&polyline(&arc(12.0, 12.0, 7.5, -0.6, 4.4), w));
            p.extend(&polyline(&[(5.6, 2.6), (9.7, 4.9), (7.6, 9.0)], w));
        }
        Icon::LogOut => {
            p.extend(&polyline(&[(13.0, 4.0), (5.0, 4.0), (5.0, 20.0), (13.0, 20.0)], w));
            p.extend(&polyline(&[(10.0, 12.0), (20.5, 12.0)], w));
            p.extend(&polyline(&[(17.0, 8.5), (20.5, 12.0), (17.0, 15.5)], w));
        }
        Icon::Bluetooth => {
            p.extend(&polyline(&[(6.5, 7.5), (17.0, 16.5), (12.0, 21.0), (12.0, 3.0), (17.0, 7.5), (6.5, 16.5)], w));
        }
        Icon::Activity => {
            p.extend(&polyline(&[(2.5, 12.5), (7.0, 12.5), (9.5, 6.0), (14.0, 19.0), (16.5, 12.5), (21.5, 12.5)], w));
        }
        Icon::Cards => {
            // The card behind shows its top and left edges.
            p.extend(&polyline(&[(5.0, 16.5), (5.0, 5.5), (6.5, 4.0), (14.0, 4.0)], w));
            p.extend(&Path::rounded_ring(8.0, 7.0, 11.5, 14.0, 2.0, w));
            let mut d = Path::new();
            d.move_to(13.75, 10.5).line_to(16.0, 14.0).line_to(13.75, 17.5).line_to(11.5, 14.0).close();
            p.extend(&d);
        }
        Icon::Flag => {
            p.extend(&polyline(&[(7.0, 21.0), (7.0, 3.5)], w));
            p.extend(&polyline(&[(7.0, 4.0), (18.5, 8.0), (7.0, 12.0)], w));
            p.extend(&polyline(&[(4.0, 21.0), (12.0, 21.0)], w));
        }
        Icon::Download => {
            p.extend(&polyline(&[(12.0, 3.5), (12.0, 14.5)], w));
            p.extend(&polyline(&[(7.5, 10.0), (12.0, 14.5), (16.5, 10.0)], w));
            p.extend(&polyline(&[(4.0, 14.0), (4.0, 20.0), (20.0, 20.0), (20.0, 14.0)], w));
        }
        Icon::People => {
            p.extend(&ring(9.0, 8.5, 3.25, w));
            p.extend(&polyline(&arc(9.0, 20.0, 6.0, core::f32::consts::PI, core::f32::consts::TAU), w));
            p.extend(&polyline(&arc(16.5, 8.5, 3.0, -1.4, 1.4), w));
            p.extend(&polyline(&arc(16.0, 20.0, 5.5, -1.05, 0.0), w));
        }
        Icon::Home => {
            p.extend(&polyline(&[(3.5, 11.5), (12.0, 4.0), (20.5, 11.5)], w));
            p.extend(&polyline(&[(6.0, 9.5), (6.0, 20.0), (18.0, 20.0), (18.0, 9.5)], w));
            p.extend(&polyline(&[(10.0, 20.0), (10.0, 14.5), (14.0, 14.5), (14.0, 20.0)], w));
        }
        Icon::Disk => {
            p.extend(&Path::rounded_ring(3.0, 6.0, 18.0, 12.0, 2.5, w));
            p.extend(&polyline(&[(3.5, 13.5), (20.5, 13.5)], w));
            p.extend(&Path::circle(17.0, 15.75, 1.1));
        }
        Icon::Trash => {
            p.extend(&polyline(&[(4.0, 6.5), (20.0, 6.5)], w));
            p.extend(&polyline(&[(9.5, 6.5), (9.5, 4.0), (14.5, 4.0), (14.5, 6.5)], w));
            p.extend(&polyline(&[(6.0, 6.5), (7.0, 20.0), (17.0, 20.0), (18.0, 6.5)], w));
            p.extend(&polyline(&[(10.0, 10.0), (10.0, 16.5)], w));
            p.extend(&polyline(&[(14.0, 10.0), (14.0, 16.5)], w));
        }
        Icon::Archive => {
            p.extend(&Path::rounded_ring(3.5, 8.0, 17.0, 12.5, 1.5, w));
            p.extend(&Path::rounded_ring(2.5, 4.0, 19.0, 4.0, 1.0, w));
            p.extend(&polyline(&[(12.0, 9.5), (12.0, 11.0)], w));
            p.extend(&polyline(&[(12.0, 13.0), (12.0, 14.5)], w));
            p.extend(&polyline(&[(12.0, 16.5), (12.0, 18.0)], w));
        }
        Icon::Window => {
            p.extend(&Path::rounded_ring(3.0, 4.5, 18.0, 15.0, 2.5, w));
            p.extend(&polyline(&[(3.5, 9.0), (20.5, 9.0)], w));
        }
        Icon::Speaker => {
            p.extend(&polyline(
                &[(4.0, 9.5), (8.0, 9.5), (13.0, 5.0), (13.0, 19.0), (8.0, 14.5), (4.0, 14.5), (4.0, 9.5)],
                w,
            ));
            p.extend(&polyline(&arc(13.0, 12.0, 4.0, -0.8, 0.8), w));
            p.extend(&polyline(&arc(13.0, 12.0, 7.5, -0.85, 0.85), w));
        }
        Icon::SpeakerMuted => {
            p.extend(&polyline(
                &[(4.0, 9.5), (8.0, 9.5), (13.0, 5.0), (13.0, 19.0), (8.0, 14.5), (4.0, 14.5), (4.0, 9.5)],
                w,
            ));
            p.extend(&polyline(&[(16.0, 9.5), (21.0, 14.5)], w));
            p.extend(&polyline(&[(21.0, 9.5), (16.0, 14.5)], w));
        }
        Icon::Sun => {
            p.extend(&polyline(&arc(12.0, 12.0, 4.0, 0.0, 2.0 * core::f32::consts::PI), w));
            for i in 0..8 {
                let a = i as f32 * core::f32::consts::FRAC_PI_4;
                let (c, s) = (cos(a), sin(a));
                p.extend(&polyline(&[(12.0 + 6.5 * c, 12.0 + 6.5 * s), (12.0 + 9.0 * c, 12.0 + 9.0 * s)], w));
            }
        }
        Icon::Moon => {
            // The outer edge round the bottom left, then back along the
            // circle that bites it (they meet at about (11, 4) and (20, 13)).
            let mut pts = arc(12.0, 12.0, 8.0, 0.128, 4.585);
            pts.extend(arc(16.5, 7.5, 6.5, 3.698, 1.014));
            pts.push(pts[0]);
            p.extend(&polyline(&pts, w));
        }
        Icon::Mouse => {
            p.extend(&Path::rounded_ring(6.5, 3.5, 11.0, 17.0, 5.5, w));
            p.extend(&polyline(&[(12.0, 6.5), (12.0, 10.0)], w));
        }
        Icon::Bell => {
            p.extend(&polyline(&[(5.0, 17.0), (6.5, 15.0), (6.5, 10.5)], w));
            p.extend(&polyline(&arc(12.0, 10.5, 5.5, core::f32::consts::PI, 2.0 * core::f32::consts::PI), w));
            p.extend(&polyline(&[(17.5, 10.5), (17.5, 15.0), (19.0, 17.0), (5.0, 17.0)], w));
            p.extend(&polyline(&arc(12.0, 18.5, 2.0, 0.0, core::f32::consts::PI), w));
        }
        Icon::BellOff => {
            p.extend(&polyline(&[(5.0, 17.0), (6.5, 15.0), (6.5, 10.5)], w));
            p.extend(&polyline(&arc(12.0, 10.5, 5.5, core::f32::consts::PI, 2.0 * core::f32::consts::PI), w));
            p.extend(&polyline(&[(17.5, 10.5), (17.5, 15.0), (19.0, 17.0), (5.0, 17.0)], w));
            p.extend(&polyline(&arc(12.0, 18.5, 2.0, 0.0, core::f32::consts::PI), w));
            p.extend(&polyline(&[(4.0, 4.0), (20.0, 20.0)], w));
        }
        Icon::Display => {
            p.extend(&Path::rounded_ring(2.5, 4.0, 19.0, 12.5, 2.0, w));
            p.extend(&polyline(&[(12.0, 16.5), (12.0, 19.5)], w));
            p.extend(&polyline(&[(8.0, 19.75), (16.0, 19.75)], w));
        }
        Icon::Picture => {
            p.extend(&Path::rounded_ring(3.0, 4.5, 18.0, 15.0, 2.0, w));
            p.extend(&polyline(&[(4.0, 17.5), (9.5, 11.5), (13.5, 15.5), (16.0, 13.0), (20.0, 17.0)], w));
            p.extend(&Path::circle(15.5, 8.75, 1.6));
        }
        Icon::Info => {
            p.extend(&ring(12.0, 12.0, 9.0, w));
            p.extend(&polyline(&[(12.0, 11.0), (12.0, 16.5)], w));
            p.extend(&Path::circle(12.0, 7.75, 1.25));
        }
        Icon::Backspace => {
            p.extend(&polyline(&[(9.0, 5.5), (20.5, 5.5), (20.5, 18.5), (9.0, 18.5), (2.5, 12.0), (9.0, 5.5)], w));
            p.extend(&polyline(&[(11.5, 9.0), (17.5, 15.0)], w));
            p.extend(&polyline(&[(17.5, 9.0), (11.5, 15.0)], w));
        }
        Icon::Sliders => {
            for (y, knob) in [(6.0, 15.0), (12.0, 8.0), (18.0, 13.0)] {
                p.extend(&polyline(&[(4.0, y), (knob - 2.5, y)], w));
                p.extend(&polyline(&[(knob + 2.5, y), (20.0, y)], w));
                p.extend(&ring(knob, y, 2.5, w));
            }
        }
        Icon::Search => {
            p.extend(&ring(10.5, 10.5, 6.5, w));
            p.extend(&polyline(&[(15.3, 15.3), (20.0, 20.0)], w));
        }
        Icon::Folder => {
            let pts =
                [(3.0, 6.0), (9.5, 6.0), (11.5, 8.5), (21.0, 8.5), (21.0, 18.5), (3.0, 18.5), (3.0, 6.0), (9.5, 6.0)];
            p.extend(&polyline(&pts, w));
        }
        Icon::Document => {
            let page = [(6.0, 3.0), (14.0, 3.0), (18.0, 7.0), (18.0, 21.0), (6.0, 21.0), (6.0, 3.0), (14.0, 3.0)];
            p.extend(&polyline(&page, w));
            p.extend(&polyline(&[(14.0, 3.0), (14.0, 7.0), (18.0, 7.0)], w));
            p.extend(&polyline(&[(9.0, 12.0), (15.0, 12.0)], w));
            p.extend(&polyline(&[(9.0, 16.0), (13.0, 16.0)], w));
        }
        Icon::Letter => {
            p.extend(&polyline(&[(5.5, 7.5), (5.5, 5.0), (18.5, 5.0), (18.5, 7.5)], w));
            p.extend(&polyline(&[(12.0, 5.0), (12.0, 19.0)], w));
            p.extend(&polyline(&[(9.0, 19.0), (15.0, 19.0)], w));
        }
        Icon::Undo => {
            // From the left, down and round clockwise to the upper left.
            p.extend(&polyline(&arc(12.0, 12.0, 8.5, core::f32::consts::PI, -2.36), w));
            p.extend(&polyline(&[(3.5, 4.0), (3.5, 9.5), (9.0, 9.5)], w));
        }
        Icon::Terminal => {
            p.extend(&Path::rounded_ring(2.5, 4.0, 19.0, 16.0, 2.5, w));
            p.extend(&polyline(&[(6.5, 9.0), (9.5, 12.0), (6.5, 15.0)], w));
            p.extend(&polyline(&[(11.5, 15.0), (16.5, 15.0)], w));
        }
        Icon::Power => {
            p.extend(&polyline(&arc(12.0, 13.0, 7.5, -1.05, -2.09 + 2.0 * core::f32::consts::PI), w));
            p.extend(&polyline(&[(12.0, 3.0), (12.0, 11.5)], w));
        }
        Icon::Enter => {
            p.extend(&polyline(&[(19.0, 5.0), (19.0, 14.0), (5.5, 14.0)], w));
            p.extend(&polyline(&[(9.5, 10.0), (5.5, 14.0), (9.5, 18.0)], w));
        }
        Icon::UpDown => {
            p.extend(&polyline(&[(8.0, 20.0), (8.0, 4.5)], w));
            p.extend(&polyline(&[(4.5, 8.0), (8.0, 4.5), (11.5, 8.0)], w));
            p.extend(&polyline(&[(16.0, 4.0), (16.0, 19.5)], w));
            p.extend(&polyline(&[(12.5, 16.0), (16.0, 19.5), (19.5, 16.0)], w));
        }
        Icon::LeftRight => {
            p.extend(&polyline(&[(20.0, 8.0), (4.5, 8.0)], w));
            p.extend(&polyline(&[(8.0, 4.5), (4.5, 8.0), (8.0, 11.5)], w));
            p.extend(&polyline(&[(4.0, 16.0), (19.5, 16.0)], w));
            p.extend(&polyline(&[(16.0, 12.5), (19.5, 16.0), (16.0, 19.5)], w));
        }
        Icon::Minimize => {
            p.extend(&polyline(&[(5.0, 18.0), (19.0, 18.0)], w));
        }
        Icon::Maximize => {
            p.extend(&Path::rounded_ring(5.0, 5.0, 14.0, 14.0, 1.5, w));
        }
        Icon::Restore => {
            p.extend(&Path::rounded_ring(4.0, 9.0, 11.0, 11.0, 1.5, w));
            p.extend(&polyline(&[(9.0, 9.0), (9.0, 4.0), (20.0, 4.0), (20.0, 15.0), (15.0, 15.0)], w));
        }
        Icon::Warning => {
            p.extend(&polyline(&[(12.0, 3.5), (21.5, 20.0), (2.5, 20.0), (12.0, 3.5), (21.5, 20.0)], w));
            p.extend(&polyline(&[(12.0, 9.5), (12.0, 14.0)], w));
            p.extend(&Path::circle(12.0, 17.0, 1.1));
        }
    }
    p.fill(canvas, &t, color);
}

/// The mouse pointer at (x, y), `s` device pixels per unit: an arrow in
/// ink with a light edge, readable on light and dark surfaces.
pub fn pointer(canvas: &mut Canvas, x: f32, y: f32, s: f32) {
    let arrow = [(0.0, 0.0), (0.0, 16.0), (4.0, 12.5), (7.0, 19.0), (9.5, 18.0), (6.5, 11.5), (11.5, 11.5)];
    let t = Transform::new(s, x, y);
    Path::polygon(&arrow).fill(canvas, &t, Color::rgb(0x0B0B0B));
    let mut edge: alloc::vec::Vec<(f32, f32)> = arrow.to_vec();
    edge.push(arrow[0]);
    edge.push(arrow[1]);
    polyline(&edge, 1.2).fill(canvas, &t, Color::rgb(0xF3F2F2));
}

/// The pointer's shapes: the arrow, and the double arrows over window
/// edges that resize (ADR 0039).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Cursor {
    #[default]
    Arrow,
    /// Left and right edges.
    ResizeH,
    /// Top and bottom edges.
    ResizeV,
    /// Top-left and bottom-right corners.
    ResizeNwse,
    /// Top-right and bottom-left corners.
    ResizeNesw,
    /// A link or a button: a pointing hand, its fingertip at the point
    /// (ADR 0186).
    Hand,
    /// Text: a beam centred at the point.
    Text,
    /// Busy: the arrow with a turning ring beside it, at step `n` of 12.
    Busy(u8),
    /// Moving something: arrows four ways, centred at the point.
    Move,
    /// Not here: a ring with a bar across, centred at the point.
    NotAllowed,
}

/// Ink with a light edge, as the arrow is drawn.
fn inked(canvas: &mut Canvas, t: &Transform, pts: &[(f32, f32)]) {
    Path::polygon(pts).fill(canvas, t, Color::rgb(0x0B0B0B));
    let mut edge: alloc::vec::Vec<(f32, f32)> = pts.to_vec();
    edge.push(pts[0]);
    edge.push(pts[1]);
    polyline(&edge, 1.2).fill(canvas, t, Color::rgb(0xF3F2F2));
}

/// The pointer at (x, y) in `shape`; a double arrow is centred there.
pub fn cursor(canvas: &mut Canvas, x: f32, y: f32, s: f32, shape: Cursor) {
    let t = Transform::new(s, x, y);
    let angle = match shape {
        Cursor::Arrow => return pointer(canvas, x, y, s),
        Cursor::ResizeH => 0.0,
        Cursor::ResizeV => core::f32::consts::FRAC_PI_2,
        Cursor::ResizeNwse => core::f32::consts::FRAC_PI_4,
        Cursor::ResizeNesw => -core::f32::consts::FRAC_PI_4,
        Cursor::Hand => {
            // The index finger up, three fingers folded, the thumb out.
            let hand = [
                (-1.8, 1.2),
                (0.0, 0.0),
                (1.8, 1.2),
                (1.8, 8.0),
                (4.6, 7.6),
                (7.0, 8.4),
                (9.0, 9.6),
                (9.0, 15.0),
                (7.0, 19.5),
                (-2.5, 19.5),
                (-6.5, 13.5),
                (-6.5, 11.0),
                (-4.5, 10.5),
                (-1.8, 12.5),
            ];
            inked(canvas, &t, &hand);
            // The folded fingers' creases.
            for cx in [4.6, 7.0] {
                polyline(&[(cx - 0.2, 8.2), (cx - 0.2, 11.5)], 1.0).fill(canvas, &t, Color::rgb(0xF3F2F2));
            }
            return;
        }
        Cursor::Text => {
            let beam = [
                (-3.5, -9.0),
                (3.5, -9.0),
                (3.5, -7.4),
                (0.9, -7.4),
                (0.9, 7.4),
                (3.5, 7.4),
                (3.5, 9.0),
                (-3.5, 9.0),
                (-3.5, 7.4),
                (-0.9, 7.4),
                (-0.9, -7.4),
                (-3.5, -7.4),
            ];
            return inked(canvas, &t, &beam);
        }
        Cursor::Busy(n) => {
            pointer(canvas, x, y, s);
            // A ring three quarters round, turning a twelfth each step.
            let a0 = f32::from(n % 12) * core::f32::consts::PI / 6.0;
            let ring = arc(15.0, 19.0, 4.0, a0, a0 + 4.7);
            polyline(&ring, 3.6).fill(canvas, &t, Color::rgb(0xF3F2F2));
            polyline(&ring, 1.8).fill(canvas, &t, Color::rgb(0x0B0B0B));
            return;
        }
        Cursor::Move => {
            let a = 2.0;
            let arm = [
                (-a, -6.0),
                (-4.5, -6.0),
                (0.0, -10.5),
                (4.5, -6.0),
                (a, -6.0),
                (a, -a),
                (6.0, -a),
                (6.0, -4.5),
                (10.5, 0.0),
                (6.0, 4.5),
                (6.0, a),
                (a, a),
                (a, 6.0),
                (4.5, 6.0),
                (0.0, 10.5),
                (-4.5, 6.0),
                (-a, 6.0),
                (-a, a),
                (-6.0, a),
                (-6.0, 4.5),
                (-10.5, 0.0),
                (-6.0, -4.5),
                (-6.0, -a),
                (-a, -a),
            ];
            return inked(canvas, &t, &arm);
        }
        Cursor::NotAllowed => {
            let ring = arc(0.0, 0.0, 7.0, 0.0, 2.0 * core::f32::consts::PI);
            polyline(&ring, 4.2).fill(canvas, &t, Color::rgb(0xF3F2F2));
            polyline(&[(-5.5, 4.5), (5.5, -4.5)], 4.2).fill(canvas, &t, Color::rgb(0xF3F2F2));
            polyline(&ring, 2.2).fill(canvas, &t, Color::rgb(0x0B0B0B));
            polyline(&[(-4.9, 4.0), (4.9, -4.0)], 2.2).fill(canvas, &t, Color::rgb(0x0B0B0B));
            return;
        }
    };
    // A horizontal double arrow, turned.
    let shape = [
        (-10.0, 0.0),
        (-5.0, -5.0),
        (-5.0, -2.0),
        (5.0, -2.0),
        (5.0, -5.0),
        (10.0, 0.0),
        (5.0, 5.0),
        (5.0, 2.0),
        (-5.0, 2.0),
        (-5.0, 5.0),
    ];
    let (c, sn) = (cos(angle), sin(angle));
    let pts: alloc::vec::Vec<(f32, f32)> = shape.iter().map(|&(px, py)| (px * c - py * sn, px * sn + py * c)).collect();
    inked(canvas, &t, &pts);
}

/// A battery `size` device pixels square at (x, y), charged `level` (0 to
/// 100).
pub fn battery(canvas: &mut Canvas, x: f32, y: f32, size: f32, level: u8, color: Color) {
    draw(canvas, Icon::Battery, x, y, size, color);
    let t = Transform::new(size / 24.0, x, y);
    let full = 13.0 * f32::from(level.min(100)) / 100.0;
    if full > 0.0 {
        Path::rect(4.5, 9.5, full, 5.0).fill(canvas, &t, color);
    }
}

/// Points along a circular arc from angle `a0` to `a1` (radians, y down).
fn arc(cx: f32, cy: f32, r: f32, a0: f32, a1: f32) -> alloc::vec::Vec<(f32, f32)> {
    let n = 24;
    (0..=n)
        .map(|i| {
            let a = a0 + (a1 - a0) * i as f32 / n as f32;
            (cx + r * cos(a), cy + r * sin(a))
        })
        .collect()
}

/// Points along a cubic Bézier, the start left out.
fn cubic(p0: (f32, f32), p1: (f32, f32), p2: (f32, f32), p3: (f32, f32)) -> alloc::vec::Vec<(f32, f32)> {
    let n = 12;
    (1..=n)
        .map(|i| {
            let t = i as f32 / n as f32;
            let u = 1.0 - t;
            let (a, b, c, d) = (u * u * u, 3.0 * u * u * t, 3.0 * u * t * t, t * t * t);
            (a * p0.0 + b * p1.0 + c * p2.0 + d * p3.0, a * p0.1 + b * p1.1 + c * p2.1 + d * p3.1)
        })
        .collect()
}

/// A circle outline as a stroke.
fn ring(cx: f32, cy: f32, r: f32, w: f32) -> Path {
    let mut pts = alloc::vec::Vec::new();
    for i in 0..=48 {
        let a = core::f32::consts::TAU * i as f32 / 48.0;
        pts.push((cx + r * cos(a), cy + r * sin(a)));
    }
    pts.push(pts[1]);
    polyline(&pts, w)
}

/// sin and cos (Taylor series after reduction to [−π/2, π/2]; plenty for
/// drawing).
pub fn sin(x: f32) -> f32 {
    let pi = core::f32::consts::PI;
    let mut x = x;
    while x > pi {
        x -= 2.0 * pi;
    }
    while x < -pi {
        x += 2.0 * pi;
    }
    // sin(π − x) = sin(x): fold into [−π/2, π/2], where the series is
    // accurate.
    if x > pi / 2.0 {
        x = pi - x;
    } else if x < -pi / 2.0 {
        x = -pi - x;
    }
    let x2 = x * x;
    x * (1.0 - x2 / 6.0 * (1.0 - x2 / 20.0 * (1.0 - x2 / 42.0 * (1.0 - x2 / 72.0 * (1.0 - x2 / 110.0)))))
}

pub fn cos(x: f32) -> f32 {
    sin(x + core::f32::consts::FRAC_PI_2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trig() {
        for i in -20..=20 {
            let a = i as f32 * 0.3;
            assert!((sin(a) - std::primitive::f32::sin(a)).abs() < 1e-4, "sin {a}");
            assert!((cos(a) - std::primitive::f32::cos(a)).abs() < 1e-4, "cos {a}");
        }
    }
}
