// SPDX-License-Identifier: MIT OR Apache-2.0

//! `strata-notify` (ADR 0186): a notification on the desktop from the
//! command line, as `notify-send` does elsewhere.
//!
//! ```text
//! strata-notify [-u low|normal|critical] [-a APP] SUMMARY [BODY]
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use slate_strata_client::{Connection, urgency};

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
pub struct Asked {
    pub app: String,
    pub summary: String,
    pub body: String,
    pub urgency: u8,
}

/// Read the arguments (without the program's name).
pub fn parse(args: &[String]) -> Result<Asked, String> {
    let mut app = String::from("Terminal");
    let mut level = urgency::NORMAL;
    let mut words: Vec<&str> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-u" | "--urgency" => {
                level = match it.next().map(String::as_str) {
                    Some("low") => urgency::LOW,
                    Some("normal") => urgency::NORMAL,
                    Some("critical") => urgency::CRITICAL,
                    other => return Err(alloc::format!("not an urgency: {}", other.unwrap_or(""))),
                }
            }
            "-a" | "--app-name" => app = it.next().cloned().ok_or("-a needs a name")?,
            w => words.push(w),
        }
    }
    let summary = words.first().ok_or("usage: strata-notify [-u low|normal|critical] [-a APP] SUMMARY [BODY]")?;
    Ok(Asked {
        app,
        summary: String::from(*summary),
        body: words.get(1..).map(|w| w.join(" ")).unwrap_or_default(),
        urgency: level,
    })
}

pub fn main() -> i32 {
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from(slate_rt::lossy(a))).collect();
    let asked = match parse(&args) {
        Ok(a) => a,
        Err(e) => {
            slate_rt::eprintln!("strata-notify: {e}");
            return 2;
        }
    };
    match Connection::connect().and_then(|mut c| c.notify(0, &asked.app, &asked.summary, &asked.body, asked.urgency)) {
        Ok(()) => 0,
        Err(e) => {
            slate_rt::eprintln!("strata-notify: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| String::from(*s)).collect()
    }

    #[test]
    fn arguments() {
        let a = parse(&args(&["Backup done", "3", "files"])).unwrap();
        assert_eq!((a.summary.as_str(), a.body.as_str(), a.urgency), ("Backup done", "3 files", urgency::NORMAL));
        assert_eq!(a.app, "Terminal");
        let a = parse(&args(&["-u", "critical", "-a", "Backup", "Disk full"])).unwrap();
        assert_eq!((a.app.as_str(), a.summary.as_str(), a.urgency), ("Backup", "Disk full", urgency::CRITICAL));
        assert!(parse(&args(&[])).is_err());
        assert!(parse(&args(&["-u", "loud", "x"])).is_err());
    }
}
