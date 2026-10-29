// SPDX-License-Identifier: MIT OR Apache-2.0

//! The power dialog (ADR 0110): the top bar's power button opens it over
//! the dimmed desktop, with four choices: lock the screen, log out,
//! restart and shut down. Restart and shut down go to the privilege
//! broker, which grants them to the session's Strata without a password,
//! as it does to the login screen: whoever sits at the machine can reach
//! its power button anyway.
//!
//! Under the choices, for restarting and shutting down (ADR 0110's
//! addendum): when, now or in 15, 30 or 60 minutes (the top bar then
//! shows when, and the dialog offers to call it off), and, when the
//! Software Updater's last check found updates, whether to install them
//! first. Before the session ends Strata asks every window to close;
//! apps that keep theirs open (unsaved work) are listed in the dialog's
//! other face ([`Ask`]), with "anyway" and Cancel.
//!
//! Keys: left and right (or Tab) choose, down goes to the options under
//! the choices and up back, Space picks an option, Enter goes, Esc
//! cancels.

use alloc::string::String;
use alloc::vec::Vec;

use slate_display::input::{
    KEY_DOWN, KEY_ENTER, KEY_ESC, KEY_KPENTER, KEY_LEFT, KEY_RIGHT, KEY_SPACE, KEY_TAB, KEY_UP,
};

use crate::draw::PowerChoice;

/// When a restart or shut down happens: its label and minutes from now.
pub const WHEN: [(&str, u32); 4] = [("now", 0), ("15 min", 15), ("30 min", 30), ("1 hour", 60)];

/// What the dialog asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub choice: PowerChoice,
    /// Minutes from now (0: at once).
    pub minutes: u32,
    /// Install the updates the last check found first.
    pub install: bool,
}

impl Plan {
    pub fn now(choice: PowerChoice) -> Plan {
        Plan { choice, minutes: 0, install: false }
    }

    /// Whether the plan ends the session (all but locking).
    pub fn leaves(&self) -> bool {
        self.choice != PowerChoice::Lock
    }

    /// The broker's action for it, if it has one.
    pub fn action(&self) -> Option<&'static str> {
        match self.choice {
            PowerChoice::Restart => Some("restart"),
            PowerChoice::ShutDown => Some("poweroff"),
            _ => None,
        }
    }
}

/// What the dialog asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Cancel,
    Go(Plan),
    /// Call off the restart or shut down set for later.
    Unschedule,
    /// Go on although apps are still open, or the updates weren't
    /// installed.
    Anyway(PowerChoice),
}

/// Which row the keys are in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Row {
    Choices,
    Options,
}

/// Why the dialog asks before going on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// These apps' windows didn't close (they ask about unsaved work).
    Unsaved,
    /// The Software Updater didn't install the updates.
    NotInstalled,
}

/// The dialog's other face: going on anyway, or not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ask {
    pub choice: PowerChoice,
    pub why: Why,
    /// The windows still open (their titles).
    pub apps: Vec<String>,
    /// 0: Cancel, 1: anyway (Cancel first: nothing is lost by it).
    pub focus: usize,
}

impl Ask {
    /// The button that goes on: "Shut down anyway".
    pub fn anyway(&self) -> String {
        alloc::format!("{} anyway", self.choice.label())
    }
}

/// A restart or shut down set for later, as the dialog shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    pub choice: PowerChoice,
    /// The local time it happens ("21:45").
    pub clock: String,
    pub install: bool,
    /// The seconds left, in the last minute.
    pub soon: Option<i64>,
}

impl Pending {
    /// What is set for `at` (monotonic ms) as it looks at `now`.
    pub fn at(choice: PowerChoice, clock: &str, install: bool, at: i64, now: i64) -> Pending {
        let left = at - now;
        let soon = (left < 60_000).then(|| (left.max(0) + 999) / 1000);
        Pending { choice, clock: String::from(clock), install, soon }
    }

    /// "Shutting down at 21:45", or "in 40 s" in the last minute.
    pub fn text(&self) -> String {
        let doing = match self.choice {
            PowerChoice::Restart => "Restarting",
            _ => "Shutting down",
        };
        match self.soon {
            Some(s) => alloc::format!("{doing} in {s} s"),
            None => alloc::format!("{doing} at {}", self.clock),
        }
    }

    /// The button that calls it off.
    pub fn undo(&self) -> &'static str {
        match self.choice {
            PowerChoice::Restart => "Don't restart",
            _ => "Don't shut down",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Power {
    pub focus: PowerChoice,
    pub focus_visible: bool,
    /// What went wrong with the last choice.
    pub error: Option<String>,
    pub row: Row,
    /// The chosen [`WHEN`].
    pub when: usize,
    /// The option the keys are on, in the options row.
    pub at: usize,
    /// Updates waiting (0: no "install first" box).
    pub updates: usize,
    pub install: bool,
    /// What is set for later; the options row then only calls it off.
    pub pending: Option<Pending>,
    pub ask: Option<Ask>,
}

impl Power {
    /// The dialog, with `focus` chosen (Shut down from the power button).
    pub fn new(focus: PowerChoice) -> Power {
        Power {
            focus,
            focus_visible: false,
            error: None,
            row: Row::Choices,
            when: 0,
            at: 0,
            updates: 0,
            install: false,
            pending: None,
            ask: None,
        }
    }

    /// With `n` updates waiting to be offered.
    pub fn with_updates(mut self, n: usize) -> Power {
        self.updates = n;
        self
    }

    pub fn with_pending(mut self, p: Option<Pending>) -> Power {
        self.pending = p;
        self
    }

    /// The other face: `choice` waits for `apps`, or for updates that
    /// weren't installed.
    pub fn asking(choice: PowerChoice, why: Why, apps: Vec<String>) -> Power {
        Power { ask: Some(Ask { choice, why, apps, focus: 0 }), ..Power::new(choice) }
    }

    fn index(&self) -> usize {
        PowerChoice::ALL.iter().position(|c| *c == self.focus).unwrap_or(0)
    }

    /// Whether when and the updates apply to the chosen tile.
    pub fn timed(&self) -> bool {
        matches!(self.focus, PowerChoice::Restart | PowerChoice::ShutDown)
    }

    /// How many options the row under the tiles has now.
    pub fn options(&self) -> usize {
        if self.pending.is_some() {
            1
        } else if self.timed() {
            WHEN.len() + usize::from(self.updates > 0)
        } else {
            0
        }
    }

    /// What going with the chosen tile asks for.
    pub fn plan(&self) -> Plan {
        if !self.timed() {
            return Plan::now(self.focus);
        }
        Plan { choice: self.focus, minutes: WHEN[self.when].1, install: self.install && self.updates > 0 }
    }

    /// Space (or a click) on option `i`.
    fn pick(&mut self, i: usize) -> Option<Outcome> {
        if self.pending.is_some() {
            return Some(Outcome::Unschedule);
        }
        if i < WHEN.len() {
            self.when = i;
        } else {
            self.install = !self.install;
        }
        None
    }

    /// A key: its evdev code, and whether shift is down.
    pub fn key(&mut self, code: u16, shift: bool) -> Option<Outcome> {
        self.focus_visible = true;
        if let Some(a) = self.ask.as_mut() {
            match code {
                KEY_ESC => return Some(Outcome::Cancel),
                KEY_ENTER | KEY_KPENTER | KEY_SPACE if a.focus == 1 => return Some(Outcome::Anyway(a.choice)),
                KEY_ENTER | KEY_KPENTER | KEY_SPACE => return Some(Outcome::Cancel),
                KEY_LEFT => a.focus = 0,
                KEY_RIGHT => a.focus = 1,
                KEY_TAB => a.focus ^= 1,
                _ => {}
            }
            return None;
        }
        let n = PowerChoice::ALL.len();
        if self.row == Row::Options && self.options() == 0 {
            self.row = Row::Choices;
        }
        match (self.row, code) {
            (_, KEY_ESC) => return Some(Outcome::Cancel),
            (Row::Options, KEY_ENTER | KEY_KPENTER) if self.pending.is_some() => return Some(Outcome::Unschedule),
            (Row::Options, KEY_ENTER | KEY_KPENTER) => {
                if self.at < WHEN.len() {
                    self.when = self.at;
                }
                return Some(Outcome::Go(self.plan()));
            }
            (_, KEY_ENTER | KEY_KPENTER) => return Some(Outcome::Go(self.plan())),
            (Row::Options, KEY_SPACE) => return self.pick(self.at),
            (Row::Choices, KEY_SPACE) => return Some(Outcome::Go(self.plan())),
            (Row::Choices, KEY_DOWN) if self.options() > 0 => {
                self.row = Row::Options;
                self.at = if self.pending.is_some() { 0 } else { self.when };
            }
            (Row::Options, KEY_UP) => self.row = Row::Choices,
            (Row::Choices, KEY_LEFT) => self.focus = PowerChoice::ALL[self.index().saturating_sub(1)],
            (Row::Choices, KEY_RIGHT) => self.focus = PowerChoice::ALL[(self.index() + 1).min(n - 1)],
            (Row::Choices, KEY_TAB) if shift => self.focus = PowerChoice::ALL[(self.index() + n - 1) % n],
            (Row::Choices, KEY_TAB) => self.focus = PowerChoice::ALL[(self.index() + 1) % n],
            (Row::Options, KEY_LEFT) => self.at = self.at.saturating_sub(1),
            (Row::Options, KEY_RIGHT) => self.at = (self.at + 1).min(self.options() - 1),
            (Row::Options, KEY_TAB) if shift => self.at = (self.at + self.options() - 1) % self.options(),
            (Row::Options, KEY_TAB) => self.at = (self.at + 1) % self.options(),
            _ => {}
        }
        None
    }

    /// A click at (x, y) with where the dialog was drawn.
    pub fn click(&mut self, x: f32, y: f32, hits: &crate::draw::PowerHits) -> Option<Outcome> {
        if let Some(a) = self.ask.as_ref() {
            if hits.ask[1].contains(x, y) {
                return Some(Outcome::Anyway(a.choice));
            }
            if hits.ask[0].contains(x, y) || !hits.dialog.contains(x, y) {
                return Some(Outcome::Cancel);
            }
            return None;
        }
        if let Some(i) = hits.choices.iter().position(|a| a.contains(x, y)) {
            self.focus = PowerChoice::ALL[i];
            self.row = Row::Choices;
            return Some(Outcome::Go(self.plan()));
        }
        if hits.unschedule.is_some_and(|a| a.contains(x, y)) {
            return Some(Outcome::Unschedule);
        }
        if self.timed() && self.pending.is_none() {
            if let Some(i) = hits.when.iter().position(|a| a.contains(x, y)) {
                self.focus_visible = false;
                return self.pick(i);
            }
            if hits.install.is_some_and(|a| a.contains(x, y)) {
                self.focus_visible = false;
                return self.pick(WHEN.len());
            }
        }
        // Cancel, and anywhere outside the dialog.
        if hits.cancel.contains(x, y) || !hits.dialog.contains(x, y) {
            return Some(Outcome::Cancel);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::draw::PowerHits;
    use slate_ui::ui::Area;

    #[test]
    fn keys() {
        let mut p = Power::new(PowerChoice::ShutDown);
        assert_eq!(p.key(KEY_RIGHT, false), None);
        assert_eq!(p.focus, PowerChoice::ShutDown);
        p.key(KEY_LEFT, false);
        p.key(KEY_LEFT, false);
        assert!(p.focus == PowerChoice::LogOut && p.focus_visible);
        p.key(KEY_TAB, true);
        p.key(KEY_TAB, true);
        assert_eq!(p.focus, PowerChoice::ShutDown);
        p.key(KEY_TAB, false);
        assert_eq!(p.key(KEY_ENTER, false), Some(Outcome::Go(Plan::now(PowerChoice::Lock))));
        assert_eq!(p.key(KEY_ESC, false), Some(Outcome::Cancel));
        assert_eq!(p.key(30, false), None);
        // Locking and logging out have no options.
        p.key(KEY_DOWN, false);
        assert_eq!(p.row, Row::Choices);
    }

    #[test]
    fn later_and_updates() {
        let mut p = Power::new(PowerChoice::ShutDown).with_updates(2);
        assert_eq!(p.options(), 5);
        p.key(KEY_DOWN, false);
        assert_eq!((p.row, p.at), (Row::Options, 0));
        p.key(KEY_RIGHT, false);
        p.key(KEY_RIGHT, false);
        p.key(KEY_SPACE, false);
        assert_eq!(p.when, 2);
        // The box, past the times; right stops there.
        for _ in 0..4 {
            p.key(KEY_RIGHT, false);
        }
        assert_eq!(p.at, 4);
        p.key(KEY_SPACE, false);
        assert!(p.install);
        // Up and left: Restart, with the same options.
        p.key(KEY_UP, false);
        p.key(KEY_LEFT, false);
        let plan = Plan { choice: PowerChoice::Restart, minutes: 30, install: true };
        assert_eq!(p.key(KEY_ENTER, false), Some(Outcome::Go(plan)));
        // Enter on a time takes it.
        let mut p = Power::new(PowerChoice::ShutDown);
        p.key(KEY_DOWN, false);
        p.key(KEY_TAB, false);
        let plan = Plan { choice: PowerChoice::ShutDown, minutes: 15, install: false };
        assert_eq!(p.key(KEY_ENTER, false), Some(Outcome::Go(plan)));
        // No updates: no box, and none installed.
        assert_eq!(p.options(), WHEN.len());
        p.install = true;
        assert!(!p.plan().install);
    }

    #[test]
    fn pending_and_asking() {
        let pending = Pending::at(PowerChoice::ShutDown, "21:45", false, 20 * 60_000, 0);
        assert_eq!(pending.text(), "Shutting down at 21:45");
        assert_eq!(Pending::at(PowerChoice::Restart, "21:45", false, 41_200, 0).text(), "Restarting in 42 s");
        let mut p = Power::new(PowerChoice::Lock).with_pending(Some(pending));
        // Calling it off is there whatever the tile.
        assert_eq!(p.options(), 1);
        p.key(KEY_DOWN, false);
        assert_eq!(p.key(KEY_ENTER, false), Some(Outcome::Unschedule));
        let mut a = Power::asking(PowerChoice::Restart, Why::Unsaved, std::vec!["Text Editor".into()]);
        assert_eq!(a.ask.as_ref().unwrap().anyway(), "Restart anyway");
        assert_eq!(a.key(KEY_ENTER, false), Some(Outcome::Cancel));
        a.key(KEY_RIGHT, false);
        assert_eq!(a.key(KEY_ENTER, false), Some(Outcome::Anyway(PowerChoice::Restart)));
        a.key(KEY_TAB, false);
        assert_eq!(a.key(KEY_SPACE, false), Some(Outcome::Cancel));
    }

    #[test]
    fn clicks() {
        let mut p = Power::new(PowerChoice::ShutDown).with_updates(1);
        let mut hits = PowerHits { dialog: Area::new(100.0, 100.0, 500.0, 400.0), ..PowerHits::default() };
        for i in 0..4 {
            hits.choices[i] = Area::new(130.0 + 120.0 * i as f32, 200.0, 108.0, 96.0);
            hits.when[i] = Area::new(170.0 + 70.0 * i as f32, 320.0, 60.0, 28.0);
        }
        hits.install = Some(Area::new(130.0, 360.0, 200.0, 24.0));
        hits.cancel = Area::new(480.0, 440.0, 90.0, 36.0);
        assert_eq!(p.click(250.0, 330.0, &hits), None);
        assert_eq!(p.when, 1);
        assert_eq!(p.click(140.0, 370.0, &hits), None);
        let plan = Plan { choice: PowerChoice::ShutDown, minutes: 15, install: true };
        assert_eq!(p.click(500.0, 250.0, &hits), Some(Outcome::Go(plan)));
        assert_eq!(p.click(260.0, 250.0, &hits), Some(Outcome::Go(Plan::now(PowerChoice::LogOut))));
        assert_eq!(p.click(500.0, 450.0, &hits), Some(Outcome::Cancel));
        assert_eq!(p.click(20.0, 20.0, &hits), Some(Outcome::Cancel));
        assert_eq!(p.click(110.0, 110.0, &hits), None);
        let mut a = Power::asking(PowerChoice::ShutDown, Why::NotInstalled, Vec::new());
        hits.ask = [Area::new(300.0, 440.0, 90.0, 36.0), Area::new(400.0, 440.0, 160.0, 36.0)];
        assert_eq!(a.click(450.0, 450.0, &hits), Some(Outcome::Anyway(PowerChoice::ShutDown)));
        assert_eq!(a.click(310.0, 450.0, &hits), Some(Outcome::Cancel));
    }
}
