// SPDX-License-Identifier: MIT OR Apache-2.0

//! The job table: background and stopped jobs, their statuses and job
//! specifications (`%n`, `%+`, `%-`, `%name`, `%?text`).

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::process;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Running,
    Stopped,
    /// The last process's wait status.
    Done(i32),
}

#[derive(Clone, Debug)]
pub struct Job {
    pub id: usize,
    /// The process group (0 without job control).
    pub pgid: i32,
    /// Processes with their wait status once they ended.
    pub pids: Vec<(i32, Option<i32>)>,
    pub label: String,
    pub state: State,
}

impl Job {
    pub fn last_pid(&self) -> i32 {
        self.pids.last().map_or(0, |p| p.0)
    }
}

#[derive(Debug, Default)]
pub struct Jobs {
    pub list: Vec<Job>,
    /// Job ids, most recent last (`%+` is the last, `%-` the one before).
    order: Vec<usize>,
}

impl Jobs {
    pub fn add(&mut self, pgid: i32, pids: &[i32], label: String, stopped: bool) -> usize {
        let id = self.list.iter().map(|j| j.id).max().unwrap_or(0) + 1;
        self.list.push(Job {
            id,
            pgid,
            pids: pids.iter().map(|&p| (p, None)).collect(),
            label,
            state: if stopped { State::Stopped } else { State::Running },
        });
        self.touch(id);
        id
    }

    /// Make `id` the current job.
    pub fn touch(&mut self, id: usize) {
        self.order.retain(|&x| x != id);
        self.order.push(id);
    }

    pub fn clear(&mut self) {
        self.list.clear();
        self.order.clear();
    }

    pub fn remove(&mut self, id: usize) -> Option<Job> {
        self.order.retain(|&x| x != id);
        let i = self.list.iter().position(|j| j.id == id)?;
        Some(self.list.remove(i))
    }

    /// `+` for the current job, `-` for the previous one.
    pub fn mark(&self, id: usize) -> char {
        match self.order.iter().rev().position(|&x| x == id) {
            Some(0) => '+',
            Some(1) => '-',
            _ => ' ',
        }
    }

    /// Collect status changes without blocking.
    pub fn poll(&mut self) {
        for j in &mut self.list {
            if matches!(j.state, State::Done(_)) {
                continue;
            }
            for p in &mut j.pids {
                if p.1.is_some() {
                    continue;
                }
                match process::wait(p.0, process::WNOHANG | process::WUNTRACED | process::WCONTINUED) {
                    Ok((0, _)) => {}
                    Ok((_, s)) if process::stopped(s).is_some() => j.state = State::Stopped,
                    Ok((_, s)) if process::continued(s) => j.state = State::Running,
                    Ok((_, s)) => p.1 = Some(s),
                    // Already reaped elsewhere.
                    Err(_) => p.1 = Some(0),
                }
            }
            if j.pids.iter().all(|p| p.1.is_some()) {
                j.state = State::Done(j.pids.last().and_then(|p| p.1).unwrap_or(0));
            }
        }
    }

    /// Wait until job `id` ends or stops; its last wait status.
    pub fn wait(&mut self, id: usize) -> Option<i32> {
        let j = self.list.iter_mut().find(|j| j.id == id)?;
        for p in &mut j.pids {
            if p.1.is_none() {
                p.1 = Some(process::wait(p.0, 0).map_or(127 << 8, |(_, s)| s));
            }
        }
        let s = j.pids.last().and_then(|p| p.1).unwrap_or(0);
        j.state = State::Done(s);
        Some(s)
    }

    /// The job a specification names.
    pub fn find(&self, spec: &[u8]) -> Option<usize> {
        let s = spec.strip_prefix(b"%").unwrap_or(spec);
        match s {
            b"" | b"+" | b"%" => self.order.last().copied(),
            b"-" => self.order.iter().rev().nth(1).or(self.order.last()).copied(),
            _ if s.iter().all(u8::is_ascii_digit) => {
                let n: usize = core::str::from_utf8(s).ok()?.parse().ok()?;
                self.list.iter().find(|j| j.id == n).map(|j| j.id)
            }
            _ => {
                let (sub, text) = match s.strip_prefix(b"?") {
                    Some(t) => (true, t),
                    None => (false, s),
                };
                let mut found = self.list.iter().filter(|j| {
                    let l = j.label.as_bytes();
                    if sub { l.windows(text.len().max(1)).any(|w| w == text) } else { l.starts_with(text) }
                });
                let first = found.next()?;
                found.next().is_none().then_some(first.id)
            }
        }
    }

    /// The job running `pid`.
    pub fn by_pid(&self, pid: i32) -> Option<usize> {
        self.list.iter().find(|j| j.pids.iter().any(|p| p.0 == pid)).map(|j| j.id)
    }

    /// Report and forget finished jobs (interactive shells, before a prompt).
    pub fn notify(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        let done: Vec<usize> = self.list.iter().filter(|j| matches!(j.state, State::Done(_))).map(|j| j.id).collect();
        for id in done {
            let mark = self.mark(id);
            if let Some(j) = self.remove(id) {
                out.push(alloc::format!("[{}]{mark}  {:<24}{}", j.id, describe_state(j.state), j.label));
            }
        }
        out
    }
}

pub fn describe_state(s: State) -> String {
    match s {
        State::Running => String::from("Running"),
        State::Stopped => String::from("Stopped"),
        State::Done(st) => match (process::exited(st), process::signaled(st)) {
            (Some(0), _) => String::from("Done"),
            (Some(c), _) => alloc::format!("Exit {c}"),
            (_, Some(sig)) => String::from(slate_rt::signal::describe(sig)),
            _ => String::from("Done"),
        },
    }
}
