// SPDX-License-Identifier: MIT OR Apache-2.0

//! AppStream catalogs (ADR 0125): the AppStream specification's catalog
//! metadata, as Flathub publishes it in its repository (`appstream.xml`,
//! the `<components>` of every app), read for App Center. Only the
//! fields Slate shows are kept, from the untranslated elements (those
//! without `xml:lang`): id, name, summary, description (paragraphs and
//! list items), developer, project licence, categories, the cached icon,
//! the homepage and the newest release's version. Only desktop
//! applications are kept (`type="desktop-application"`, or the older
//! `desktop`).
//!
//! [`Component::line`] and [`Component::from_line`] keep a component on
//! one line (tab-separated, the description's parts apart), for a cache
//! that loads quickly.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod xml;

use alloc::string::String;
use alloc::vec::Vec;

use xml::{Event, Reader, collapse};

/// A part of a description: a paragraph, or an item of a list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Para {
    P(String),
    Item(String),
}

/// An application in the catalog.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Component {
    /// Its ID, as Flatpak names it (`org.gnome.Calculator`).
    pub id: String,
    pub name: String,
    pub summary: String,
    pub description: Vec<Para>,
    pub developer: String,
    pub license: String,
    /// The freedesktop menu categories (`Utility`, `Office`...).
    pub categories: Vec<String>,
    /// The cached icon's file name (beside the catalog, under
    /// `icons/64x64` and `icons/128x128`).
    pub icon: String,
    pub homepage: String,
    pub version: String,
}

/// The catalog's applications, in the order it lists them.
pub fn parse(doc: &str) -> Vec<Component> {
    let mut out = Vec::new();
    let mut c: Option<Component> = None;
    // The open elements under the component, and whether an
    // `xml:lang` (a translation) is among them.
    let mut path: Vec<(&str, bool)> = Vec::new();
    let mut text = String::new();
    let mut keep = false;
    let mut release_seen = false;
    for ev in Reader::new(doc) {
        match ev {
            Event::Start { name: "component", attrs, empty: false } if c.is_none() => {
                let kind = attrs.iter().find(|a| a.0 == "type").map_or("", |a| a.1.as_str());
                keep = matches!(kind, "desktop-application" | "desktop");
                c = Some(Component::default());
                path.clear();
                release_seen = false;
            }
            Event::Start { name, attrs, empty } if c.is_some() => {
                let attr = |k: &str| attrs.iter().find(|a| a.0 == k).map(|a| a.1.as_str());
                if name == "release" && path.last().map(|p| p.0) == Some("releases") && !release_seen {
                    // The newest release comes first (the specification's
                    // order).
                    release_seen = true;
                    if let Some(comp) = c.as_mut() {
                        comp.version = String::from(attr("version").unwrap_or(""));
                    }
                }
                if empty {
                    continue;
                }
                // Skipped: translations, and urls other than the homepage,
                // icons other than the cached one.
                let skip = attr("xml:lang").is_some()
                    || path.iter().any(|p| p.1)
                    || name == "url" && attr("type") != Some("homepage")
                    || name == "icon" && attr("type") != Some("cached");
                // Inline markup in a paragraph or item adds to its text.
                if !path.iter().any(|p| matches!(p.0, "p" | "li")) {
                    text.clear();
                }
                path.push((name, skip));
            }
            Event::Text(t) if c.is_some() => text.push_str(&t),
            Event::End("component") => {
                if let Some(done) = c.take()
                    && keep
                    && !done.id.is_empty()
                    && !done.name.is_empty()
                {
                    out.push(done);
                }
            }
            Event::End(name) if c.is_some() => {
                let Some((open, lang)) = path.pop() else { continue };
                if open != name {
                    // Mismatched tags: what is open stays as it is.
                    path.push((open, lang));
                    continue;
                }
                let comp = c.as_mut().unwrap_or_else(|| unreachable!());
                let parent = path.last().map(|p| p.0);
                let value = collapse(&text);
                if lang {
                    continue;
                }
                match (name, parent) {
                    ("id", None) => comp.id = value,
                    ("name", None) => comp.name = value,
                    ("summary", None) => comp.summary = value,
                    ("developer_name", None) => comp.developer = value,
                    ("name", Some("developer")) if comp.developer.is_empty() => comp.developer = value,
                    ("project_license", None) => comp.license = value,
                    ("category", Some("categories")) => comp.categories.push(value),
                    ("icon", None) if comp.icon.is_empty() => comp.icon = value,
                    ("url", None) if comp.homepage.is_empty() => comp.homepage = value,
                    ("p", Some("description")) if !value.is_empty() => comp.description.push(Para::P(value)),
                    ("li", Some("ul" | "ol")) if !value.is_empty() => comp.description.push(Para::Item(value)),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    out
}

/// A field for one line: no tabs, newlines or record marks.
fn flat(s: &str) -> String {
    s.chars().map(|c| if matches!(c, '\t' | '\n' | '\r' | '\x1e' | '\x1f') { ' ' } else { c }).collect()
}

impl Component {
    /// The component on one line: id, name, summary, developer, licence,
    /// categories (`;`), icon, homepage, version, description (parts
    /// apart by U+001E, items marked by U+001F), tab-separated.
    pub fn line(&self) -> String {
        let desc: Vec<String> = self
            .description
            .iter()
            .map(|p| match p {
                Para::P(t) => flat(t),
                Para::Item(t) => alloc::format!("\x1f{}", flat(t)),
            })
            .collect();
        let fields = [
            flat(&self.id),
            flat(&self.name),
            flat(&self.summary),
            flat(&self.developer),
            flat(&self.license),
            flat(&self.categories.join(";")),
            flat(&self.icon),
            flat(&self.homepage),
            flat(&self.version),
            desc.join("\x1e"),
        ];
        fields.join("\t")
    }

    /// A component from [`Component::line`]'s text.
    pub fn from_line(line: &str) -> Option<Component> {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 10 || f[0].is_empty() {
            return None;
        }
        let description = f[9]
            .split('\x1e')
            .filter(|p| !p.is_empty())
            .map(|p| match p.strip_prefix('\x1f') {
                Some(item) => Para::Item(String::from(item)),
                None => Para::P(String::from(p)),
            })
            .collect();
        Some(Component {
            id: String::from(f[0]),
            name: String::from(f[1]),
            summary: String::from(f[2]),
            developer: String::from(f[3]),
            license: String::from(f[4]),
            categories: f[5].split(';').filter(|c| !c.is_empty()).map(String::from).collect(),
            icon: String::from(f[6]),
            homepage: String::from(f[7]),
            version: String::from(f[8]),
            description,
        })
    }

    /// Whether `query` (lower case) is in its name, summary or ID.
    pub fn matches(&self, query: &str) -> bool {
        query.is_empty()
            || self.name.to_lowercase().contains(query)
            || self.summary.to_lowercase().contains(query)
            || self.id.to_lowercase().contains(query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const CATALOG: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<components version="0.14" origin="flathub">
  <component type="desktop-application">
    <id>org.gnome.Calculator</id>
    <name>Calculator</name>
    <name xml:lang="de">Taschenrechner</name>
    <summary>Perform arithmetic, scientific or financial calculations</summary>
    <summary xml:lang="de">Rechnen</summary>
    <developer id="org.gnome"><name>The GNOME Project</name></developer>
    <project_license>GPL-3.0+</project_license>
    <description>
      <p>Calculator is an application that solves <em>mathematical</em> equations.</p>
      <p xml:lang="de">Ein Rechner.</p>
      <ul><li>Basic &amp; advanced modes</li><li xml:lang="de">Grundlegend</li><li>Financial</li></ul>
    </description>
    <categories><category>Utility</category><category>Calculator</category></categories>
    <icon type="stock">accessories-calculator</icon>
    <icon type="cached" height="64" width="64">org.gnome.Calculator.png</icon>
    <url type="bugtracker">https://example.org/bugs</url>
    <url type="homepage">https://apps.gnome.org/Calculator</url>
    <releases>
      <release version="48.1" timestamp="1745000000"/>
      <release version="48.0" timestamp="1740000000"/>
    </releases>
  </component>
  <component type="runtime"><id>org.gnome.Platform</id><name>GNOME runtime</name></component>
  <component type="desktop">
    <id>org.example.Old</id>
    <name>Old style</name>
    <developer_name>Someone</developer_name>
    <summary>Tab	in it</summary>
  </component>
</components>"#;

    #[test]
    fn components() {
        let c = parse(CATALOG);
        assert_eq!(c.len(), 2, "the runtime is no app");
        let calc = &c[0];
        assert_eq!(calc.id, "org.gnome.Calculator");
        assert_eq!(calc.name, "Calculator");
        assert_eq!(calc.summary, "Perform arithmetic, scientific or financial calculations");
        assert_eq!(calc.developer, "The GNOME Project");
        assert_eq!(calc.license, "GPL-3.0+");
        assert_eq!(
            calc.description,
            vec![
                Para::P("Calculator is an application that solves mathematical equations.".into()),
                Para::Item("Basic & advanced modes".into()),
                Para::Item("Financial".into()),
            ]
        );
        assert_eq!(calc.categories, ["Utility", "Calculator"]);
        assert_eq!(calc.icon, "org.gnome.Calculator.png");
        assert_eq!(calc.homepage, "https://apps.gnome.org/Calculator");
        assert_eq!(calc.version, "48.1");
        assert_eq!(c[1].developer, "Someone");
        // One line each, and back.
        for comp in &c {
            assert_eq!(
                Component::from_line(&comp.line()).as_ref(),
                Some(&Component { ..comp.clone() })
                    .map(|x| {
                        let mut x = x.clone();
                        x.summary = x.summary.replace('\t', " ");
                        x
                    })
                    .as_ref()
            );
        }
        assert!(calc.matches("arith") && calc.matches("gnome.calc") && !calc.matches("chess"));
        assert!(Component::from_line("too\tfew").is_none());
    }
}

#[cfg(test)]
mod real {
    use super::*;

    /// Flathub's catalog as it is (`SLATE_APPSTREAM=FILE.xml`): every app
    /// read, and how long it takes. Run with `--ignored --release`.
    #[test]
    #[ignore]
    fn flathub() {
        let Ok(path) = std::env::var("SLATE_APPSTREAM") else { return };
        let text = std::fs::read_to_string(path).unwrap();
        let t = std::time::Instant::now();
        let apps = parse(&text);
        let took = t.elapsed();
        let lines: Vec<String> = apps.iter().map(|c| c.line()).collect();
        std::println!(
            "{} apps from {} MB in {:?} ({} with icons, {} with descriptions); cache {} KB",
            apps.len(),
            text.len() >> 20,
            took,
            apps.iter().filter(|c| !c.icon.is_empty()).count(),
            apps.iter().filter(|c| !c.description.is_empty()).count(),
            lines.iter().map(|l| l.len() + 1).sum::<usize>() >> 10
        );
        for l in &lines {
            assert!(Component::from_line(l).is_some());
        }
    }
}
