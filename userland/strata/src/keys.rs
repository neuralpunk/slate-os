// SPDX-License-Identifier: MIT OR Apache-2.0

//! `strata-keys`: a small Strata app listing the shortcuts, and the first
//! client of the protocol (ADR 0037). It draws with slate-ui into its
//! window's canvas and redraws when its size or focus changes, or when
//! the person's settings change the colours (a watch tells it: `watch`).

use slate_rt::io;
use slate_strata_client::{Connection, Event};
use slate_ui::paint::Painter;
use slate_ui::text::GlyphCache;
use slate_ui::ui::Area;

use crate::desktop;
use crate::fonts::Fonts;

pub fn main() -> i32 {
    let files = match crate::session::load_fonts() {
        Ok(f) => f,
        Err(e) => {
            slate_rt::eprintln!("strata-keys: {e}");
            return 1;
        }
    };
    let refs: [&[u8]; 5] = core::array::from_fn(|i| files[i].as_slice());
    let Some(fonts) = Fonts::new(refs) else { return 1 };
    let run = || -> Result<(), alloc::string::String> {
        let mut conn = Connection::connect()?;
        let mut win = conn.create("keys", Some("shortcuts"))?;
        let mut stamp = crate::settings::stamp();
        // The palette follows the settings: told of their changes, or
        // looking every two seconds where they can't be watched.
        let mut watch =
            crate::watch::Watcher::new(&slate_rt::env::var(b"HOME").unwrap_or_default(), crate::watch::SETTINGS);
        let mut pal = crate::settings::Settings::load().palette();
        let mut cache = GlyphCache::new();
        loop {
            let mut canvas = win.canvas(pal.window);
            let mut p = Painter::new(&mut canvas, &mut cache, win.scale);
            let (w, h) = p.size();
            desktop::keys_window(&mut p, &pal, &fonts, Area::new(0.0, 0.0, w, h));
            conn.present(&mut win, &canvas)?;
            let mut redraw = false;
            while !redraw {
                let mut events = conn.take_events();
                let mut changed = watch.retry() | watch.unwatched();
                if events.is_empty() {
                    let mut fds = alloc::vec![io::PollFd { fd: conn.fd(), events: io::POLLIN, revents: 0 }];
                    fds.extend(watch.fd().map(|fd| io::PollFd { fd, events: io::POLLIN, revents: 0 }));
                    let _ = io::poll(&mut fds, if watch.unwatched() != 0 { 2000 } else { -1 });
                    if fds[0].revents != 0 {
                        conn.read()?;
                        events = conn.take_events();
                    }
                    if fds.get(1).is_some_and(|p| p.revents != 0) {
                        changed |= watch.read();
                    }
                }
                if changed != 0 && crate::settings::stamp() != stamp {
                    stamp = crate::settings::stamp();
                    let new = crate::settings::Settings::load().palette();
                    redraw |= new != pal;
                    pal = new;
                }
                for e in events {
                    match e {
                        Event::Close { .. } => return Ok(()),
                        Event::Configure { .. } => {
                            win.configure(&e);
                            redraw = true;
                        }
                        _ => {}
                    }
                }
            }
        }
    };
    match run() {
        Ok(()) => 0,
        Err(e) => {
            slate_rt::eprintln!("strata-keys: {e}");
            1
        }
    }
}
