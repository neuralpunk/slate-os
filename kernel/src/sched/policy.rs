// SPDX-License-Identifier: MIT OR Apache-2.0

//! Scheduling policies, priorities and weights (sched(7), ADR 0045).
//!
//! Every thread has a *rank*: real-time threads (SCHED_FIFO, SCHED_RR)
//! rank 100 + their priority (101 to 199), normal threads 20 - nice (1 to
//! 40), SCHED_IDLE threads 0. A thread waiting on a priority-inheritance
//! futex lends its rank to the owner (`Thread::pi_boost`); the higher of
//! the two decides how the owner runs.

/// Scheduling policies. Source: musl `sched.h` (ADR 0009).
pub const SCHED_OTHER: u8 = 0;
pub const SCHED_FIFO: u8 = 1;
pub const SCHED_RR: u8 = 2;
/// SCHED_BATCH runs as SCHED_OTHER does.
#[allow(dead_code)]
pub const SCHED_BATCH: u8 = 3;
pub const SCHED_IDLE: u8 = 5;

/// The weight of a normal thread at nice 0.
pub const NICE_0_WEIGHT: u64 = 1024;
/// SCHED_IDLE runs "at an extremely low priority, lower even than a +19
/// nice value" (sched(7)).
const IDLE_WEIGHT: u64 = 3;

/// Weights for nice -20 to 19. sched(7): "each unit of difference in the
/// nice values of two processes results in a factor of 1.25 in the degree
/// to which the scheduler favors the higher priority process". Computed
/// here from 1024 at nice 0, one factor of 1.25 per step.
const WEIGHTS: [u64; 40] = weights();

const fn weights() -> [u64; 40] {
    let mut w = [0u64; 40];
    w[20] = NICE_0_WEIGHT;
    let mut i = 20;
    while i > 0 {
        w[i - 1] = (w[i] * 5 + 2) / 4;
        i -= 1;
    }
    let mut i = 20;
    while i < 39 {
        let next = (w[i] * 4 + 2) / 5;
        w[i + 1] = if next == 0 { 1 } else { next };
        i += 1;
    }
    w
}

/// The weight of a normal thread at `nice` (-20 to 19).
pub fn weight(nice: i8) -> u64 {
    WEIGHTS[(i32::from(nice).clamp(-20, 19) + 20) as usize]
}

/// The rank of a thread with these parameters.
pub fn rank(policy: u8, rt_priority: u8, nice: i8) -> u32 {
    match policy {
        SCHED_FIFO | SCHED_RR => 100 + u32::from(rt_priority),
        SCHED_IDLE => 0,
        _ => (20 - i32::from(nice).clamp(-20, 19)) as u32,
    }
}

/// How a thread runs, from its own parameters and its boost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Before every normal thread, by priority (1 to 99); `rr`: with a
    /// time slice (SCHED_RR), else until it blocks or yields (SCHED_FIFO).
    RealTime { priority: u8, rr: bool },
    /// Shares the CPU by weight.
    Fair { weight: u64 },
}

/// The class of a thread with these parameters and boost (a rank, 0 for
/// none).
pub fn class(policy: u8, rt_priority: u8, nice: i8, boost: u32) -> Class {
    let own = rank(policy, rt_priority, nice);
    if boost <= own {
        return match policy {
            SCHED_FIFO | SCHED_RR => Class::RealTime { priority: rt_priority, rr: policy == SCHED_RR },
            SCHED_IDLE => Class::Fair { weight: IDLE_WEIGHT },
            _ => Class::Fair { weight: weight(nice) },
        };
    }
    if boost > 100 {
        Class::RealTime { priority: (boost - 100) as u8, rr: policy == SCHED_RR }
    } else {
        Class::Fair { weight: weight((20 - boost as i32) as i8) }
    }
}

/// Real-time time slice (SCHED_RR), in timer ticks: 100 ms, as
/// sched_rr_get_interval(2) reports.
pub const RR_SLICE_TICKS: u32 = 100;

/// Checks of the tables (run as in-kernel tests).
pub fn self_check() -> Result<(), &'static str> {
    if weight(0) != 1024 {
        return Err("nice 0 must weigh 1024");
    }
    for n in -20..19i8 {
        let (a, b) = (weight(n), weight(n + 1));
        // Each step is a factor of 1.25, within rounding.
        if a * 4 < b * 5 - b / 8 || a * 4 > b * 5 + b / 8 + 4 {
            return Err("nice weights are not a factor of 1.25 apart");
        }
    }
    if rank(SCHED_FIFO, 1, 0) <= rank(SCHED_OTHER, 0, -20) || rank(SCHED_IDLE, 0, 0) >= rank(SCHED_OTHER, 0, 19) {
        return Err("ranks are out of order");
    }
    if class(SCHED_OTHER, 0, 10, rank(SCHED_FIFO, 50, 0)) != (Class::RealTime { priority: 50, rr: false }) {
        return Err("a real-time boost must make a normal thread real-time");
    }
    Ok(())
}
