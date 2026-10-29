// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Applications menu (ADR 0110): the drop-down under the top bar's
//! Applications button, as a desktop's menu is: categories on the left,
//! the chosen one's apps on the right, a search field above them. The
//! pointer over a category opens it; typing searches every app (ranked
//! as the launcher ranks, [`launcher::score`]).
//!
//! Keys: up and down move in the column that has the keyboard, right (or
//! Tab, or Enter on a category) goes to the apps, left back to the
//! categories, Enter opens the app, Esc clears the search or closes.

use alloc::string::String;
use alloc::vec::Vec;

use slate_display::input::{
    KEY_BACKSPACE, KEY_DOWN, KEY_ENTER, KEY_ESC, KEY_KPENTER, KEY_LEFT, KEY_PAGEDOWN, KEY_PAGEUP, KEY_RIGHT, KEY_TAB,
    KEY_UP,
};
use slate_ui::icon::Icon;

use crate::launcher::{self, App};

/// A category in the left column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Category {
    /// The apps opened last.
    Recent,
    All,
    /// A group named by the apps' `category` ("accessories", "system"...).
    Named(String),
}

impl Category {
    pub fn label(&self) -> String {
        match self {
            Category::Recent => String::from("Recently used"),
            Category::All => String::from("All applications"),
            Category::Named(n) => {
                let mut c = n.chars();
                c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default()
            }
        }
    }

    pub fn icon(&self) -> Icon {
        match self {
            Category::Recent => Icon::Clock,
            Category::All => Icon::Grid,
            Category::Named(n) => match n.as_str() {
                "accessories" => Icon::Calculator,
                "internet" => Icon::Globe,
                "office" => Icon::Briefcase,
                "graphics" => Icon::Picture,
                "sound & video" => Icon::Play,
                "development" => Icon::Code,
                "games" => Icon::Grid,
                "system" => Icon::Terminal,
                "settings" => Icon::Sliders,
                "help" => Icon::Info,
                _ => Icon::Folder,
            },
        }
    }
}

/// Which column has the keyboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pane {
    Categories,
    Apps,
}

/// What the menu asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Close,
    Open(App),
}

/// How many app rows the right column shows.
pub const APPS_SHOWN: usize = 8;

#[derive(Clone, Debug)]
pub struct Menu {
    apps: Vec<App>,
    recent: Vec<String>,
    pub categories: Vec<Category>,
    pub query: String,
    /// The chosen category.
    pub category: usize,
    /// The chosen app among those shown, and the first app row shown.
    pub item: usize,
    pub first: usize,
    pub pane: Pane,
}

impl Menu {
    /// The menu for `apps`, with the apps opened last (their `exec`, the
    /// latest first). It opens on the recent apps if there are any, else
    /// on all of them.
    pub fn new(mut apps: Vec<App>, recent: Vec<String>) -> Menu {
        apps.sort_by(|a, b| a.name.cmp(&b.name));
        let recent: Vec<String> = recent.into_iter().filter(|e| apps.iter().any(|a| a.exec == *e)).collect();
        let mut named: Vec<String> = Vec::new();
        for a in &apps {
            if !named.contains(&a.category) {
                named.push(a.category.clone());
            }
        }
        named.sort_by(|a, b| launcher::category_rank(a).cmp(&launcher::category_rank(b)));
        let mut categories = Vec::new();
        if !recent.is_empty() {
            categories.push(Category::Recent);
        }
        categories.push(Category::All);
        categories.extend(named.into_iter().map(Category::Named));
        Menu { apps, recent, categories, query: String::new(), category: 0, item: 0, first: 0, pane: Pane::Categories }
    }

    /// Searching: the categories step aside.
    pub fn searching(&self) -> bool {
        !self.query.trim().is_empty()
    }

    /// The apps in the right column: the search's matches, best first, or
    /// the chosen category's.
    pub fn shown(&self) -> Vec<&App> {
        if self.searching() {
            let mut found: Vec<(i32, &App)> =
                self.apps.iter().filter_map(|a| launcher::score(&a.name, &self.query).map(|s| (s, a))).collect();
            found.sort_by_key(|(s, _)| -s);
            return found.into_iter().map(|(_, a)| a).collect();
        }
        match self.categories.get(self.category) {
            Some(Category::Recent) => {
                self.recent.iter().filter_map(|e| self.apps.iter().find(|a| a.exec == *e)).take(APPS_SHOWN).collect()
            }
            Some(Category::Named(n)) => self.apps.iter().filter(|a| a.category == *n).collect(),
            _ => self.apps.iter().collect(),
        }
    }

    /// The app rows drawn: (index among the shown apps, app).
    pub fn window(&self) -> Vec<(usize, &App)> {
        self.shown().into_iter().enumerate().skip(self.first).take(APPS_SHOWN).collect()
    }

    /// Keep the chosen app in the rows shown.
    fn follow(&mut self) {
        let n = self.shown().len();
        self.item = self.item.min(n.saturating_sub(1));
        if self.item < self.first {
            self.first = self.item;
        } else if self.item >= self.first + APPS_SHOWN {
            self.first = self.item + 1 - APPS_SHOWN;
        }
        self.first = self.first.min(n.saturating_sub(APPS_SHOWN));
    }

    fn choose_category(&mut self, i: usize) -> bool {
        let changed = i != self.category;
        self.category = i;
        (self.item, self.first) = (0, 0);
        changed
    }

    /// The pointer over category `i` opens it.
    pub fn hover_category(&mut self, i: usize) -> bool {
        if self.searching() || i >= self.categories.len() {
            return false;
        }
        self.pane = Pane::Categories;
        self.choose_category(i)
    }

    /// The pointer over shown app row `i` (as drawn) chooses it.
    pub fn hover_app(&mut self, i: usize) -> bool {
        let j = self.first + i;
        let changed = j != self.item || self.pane != Pane::Apps;
        if j < self.shown().len() {
            (self.item, self.pane) = (j, Pane::Apps);
            return changed;
        }
        false
    }

    /// What the chosen app is, to open.
    pub fn chosen(&self) -> Option<App> {
        self.shown().get(self.item).map(|a| (*a).clone())
    }

    /// The wheel over the apps (`lines` < 0 is up).
    pub fn scroll(&mut self, lines: i32) -> bool {
        let n = self.shown().len();
        let max = n.saturating_sub(APPS_SHOWN) as i64;
        let first = (self.first as i64 + i64::from(lines)).clamp(0, max) as usize;
        if first == self.first {
            return false;
        }
        self.first = first;
        self.item = self.item.clamp(first, (first + APPS_SHOWN).min(n).saturating_sub(1));
        true
    }

    /// A key: its evdev code and the character it types.
    pub fn key(&mut self, code: u16, ch: Option<char>) -> Option<Outcome> {
        let n = self.shown().len();
        match code {
            KEY_ESC if self.searching() => {
                self.query.clear();
                (self.item, self.first, self.pane) = (0, 0, Pane::Categories);
            }
            KEY_ESC => return Some(Outcome::Close),
            KEY_ENTER | KEY_KPENTER => match self.pane {
                Pane::Categories if !self.searching() => self.pane = Pane::Apps,
                _ => return self.chosen().map(Outcome::Open),
            },
            KEY_BACKSPACE => {
                self.query.pop();
                (self.item, self.first) = (0, 0);
                if !self.searching() {
                    self.pane = Pane::Categories;
                }
            }
            KEY_RIGHT | KEY_TAB if n > 0 => self.pane = Pane::Apps,
            KEY_LEFT if !self.searching() => self.pane = Pane::Categories,
            KEY_UP | KEY_DOWN | KEY_PAGEUP | KEY_PAGEDOWN => {
                let (up, step) = match code {
                    KEY_UP => (true, 1),
                    KEY_DOWN => (false, 1),
                    KEY_PAGEUP => (true, APPS_SHOWN),
                    _ => (false, APPS_SHOWN),
                };
                match self.pane {
                    Pane::Categories if !self.searching() => {
                        let last = self.categories.len() - 1;
                        let i = if up { self.category.saturating_sub(step) } else { (self.category + step).min(last) };
                        self.choose_category(i);
                    }
                    _ => {
                        let last = n.saturating_sub(1);
                        self.item = if up { self.item.saturating_sub(step) } else { (self.item + step).min(last) };
                    }
                }
            }
            _ => {
                let c = ch.filter(|c| !c.is_control())?;
                self.query.push(c);
                (self.item, self.first, self.pane) = (0, 0, Pane::Apps);
            }
        }
        self.follow();
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(name: &str, category: &str) -> App {
        let text = alloc::format!("name={name}\nexec=/bin/{}\ncategory={category}\n", name.to_lowercase());
        launcher::parse_app(&text).unwrap()
    }

    fn apps() -> Vec<App> {
        let mut v = alloc::vec![
            app("Terminal", "System"),
            app("Calculator", "Accessories"),
            app("Clock", "Accessories"),
            app("Calendar", "Office"),
            app("Settings", "Settings"),
            app("Help", "Help"),
        ];
        v.extend((0..10).map(|i| app(&alloc::format!("Tool {i}"), "Accessories")));
        v
    }

    fn names(m: &Menu) -> Vec<&str> {
        m.shown().iter().map(|a| a.name.as_str()).collect()
    }

    #[test]
    fn categories_in_order() {
        let m = Menu::new(apps(), alloc::vec!["/bin/clock".into(), "/bin/gone".into()]);
        let labels: Vec<String> = m.categories.iter().map(Category::label).collect();
        assert_eq!(
            labels,
            ["Recently used", "All applications", "Accessories", "Office", "System", "Settings", "Help"]
        );
        assert_eq!(names(&m), ["Clock"]);
        // Without recent apps it opens on all of them.
        let m = Menu::new(apps(), Vec::new());
        assert_eq!(m.categories[0], Category::All);
        assert_eq!(m.shown().len(), 16);
    }

    #[test]
    fn keys_and_the_pointer() {
        let mut m = Menu::new(apps(), Vec::new());
        // Down to Accessories, into its apps, down the list (it scrolls).
        m.key(KEY_DOWN, None);
        assert_eq!(m.categories[m.category], Category::Named("accessories".into()));
        assert_eq!(m.key(KEY_RIGHT, None), None);
        assert_eq!(m.pane, Pane::Apps);
        for _ in 0..9 {
            m.key(KEY_DOWN, None);
        }
        assert_eq!((m.item, m.first), (9, 2));
        assert_eq!(m.key(KEY_ENTER, None), Some(Outcome::Open(m.chosen().unwrap())));
        assert_eq!(m.chosen().unwrap().name, "Tool 7");
        // Left and down: Office's one app.
        m.key(KEY_LEFT, None);
        m.key(KEY_DOWN, None);
        assert_eq!(names(&m), ["Calendar"]);
        // The pointer: over System, then its app.
        assert!(m.hover_category(3));
        assert_eq!(names(&m), ["Terminal"]);
        assert!(m.hover_app(0));
        assert_eq!(m.key(KEY_KPENTER, None).map(|o| matches!(o, Outcome::Open(a) if a.name == "Terminal")), Some(true));
        assert!(!m.hover_app(3));
        assert_eq!(m.key(KEY_ESC, None), Some(Outcome::Close));
    }

    #[test]
    fn searching() {
        let mut m = Menu::new(apps(), Vec::new());
        for c in "cal".chars() {
            m.key(0, Some(c));
        }
        assert!(m.searching() && m.pane == Pane::Apps);
        assert_eq!(names(&m), ["Calculator", "Calendar"]);
        // The categories don't follow the pointer meanwhile.
        assert!(!m.hover_category(2));
        m.key(KEY_DOWN, None);
        assert_eq!(m.chosen().unwrap().name, "Calendar");
        // Esc clears the search first, then closes.
        assert_eq!(m.key(KEY_ESC, None), None);
        assert!(!m.searching() && m.pane == Pane::Categories);
        m.key(0, Some('z'));
        m.key(KEY_BACKSPACE, None);
        assert_eq!(m.shown().len(), 16);
        assert_eq!(m.key(KEY_ESC, None), Some(Outcome::Close));
        // The wheel scrolls All's 16 apps by rows.
        assert!(m.scroll(3));
        assert_eq!((m.first, m.item), (3, 3));
        assert!(m.scroll(100));
        assert_eq!(m.first, 8);
        assert!(!m.scroll(1));
    }
}
