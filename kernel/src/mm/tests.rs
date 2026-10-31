// SPDX-License-Identifier: MIT OR Apache-2.0

//! In-kernel tests for memory management.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::alloc::Layout;

use super::vmap::KernelStack;
use super::{PAGE_SIZE, PhysAddr, frame, heap};
use crate::arch::{cpu, paging, probe};
use crate::ktest::{Rng, Test, ensure};

pub const TESTS: &[Test] = &[
    Test { name: "mm::frames_random", run: frames_random },
    Test { name: "mm::frames_exhaust_and_coalesce", run: frames_exhaust },
    Test { name: "mm::heap_stress", run: heap_stress },
    Test { name: "mm::heap_collections", run: heap_collections },
    Test { name: "mm::kernel_text_read_only", run: text_read_only },
    Test { name: "mm::stack_guard_page", run: stack_guard },
    Test { name: "mm::stacks_unmapped_when_freed", run: stacks_unmapped },
    Test { name: "mm::stack_slots_reused_safely", run: stack_slots_reused },
    Test { name: "mm::protection_features", run: protection_features },
    Test { name: "mm::scratch_memory", run: scratch_memory },
    Test { name: "mm::user_page_many_refs", run: user_page_many_refs },
    Test { name: "mm::resident_count", run: resident_count },
    Test { name: "mm::pinned_pages_stay_at_fork", run: pinned_pages_stay_at_fork },
];

/// A private page a device holds (`pins`, a GPU's 2D image) stays the
/// parent's, writable, through a fork; the child gets a copy of it in a
/// frame of its own; an unpinned page beside it is shared copy-on-write
/// as before.
fn pinned_pages_stay_at_fork() -> Result<(), &'static str> {
    use super::aspace::{AddressSpace, Fault, Prot};
    let mut a = AddressSpace::new().map_err(|_| "no address space")?;
    let base = a.map(None, 2 * PAGE_SIZE, Prot::RW, false).map_err(|_| "map failed")?;
    for i in 0..2 {
        ensure(matches!(a.handle_fault(base + i * PAGE_SIZE, true, false), Fault::Fixed), "fault not fixed")?;
    }
    let (pinned, other) = (a.translate(base).ok_or("no frame")?, a.translate(base + PAGE_SIZE).ok_or("no frame")?);
    // SAFETY: the address space's own frame, in the direct map.
    unsafe { pinned.to_virt().write_volatile(0x5A) };
    super::pins::pin(pinned);
    let b = a.fork().map_err(|_| "fork failed")?;
    super::pins::unpin(pinned);
    let copy = b.translate(base).ok_or("no frame in the child")?;
    ensure(a.translate(base) == Some(pinned), "the parent's page moved")?;
    ensure(copy != pinned, "the child shares the pinned frame")?;
    // SAFETY: the child's new frame, in the direct map.
    ensure(unsafe { copy.to_virt().read_volatile() } == 0x5A, "the child's copy differs")?;
    ensure(a.leaf_flags(base).is_some_and(|f| f.write), "the parent lost write access")?;
    ensure(b.translate(base + PAGE_SIZE) == Some(other), "the unpinned page wasn't shared")?;
    ensure(!super::pins::is_pinned(pinned), "the pin stayed")
}

/// The resident page count kept as pages come and go matches the page
/// tables through faults, fork, copy-on-write, unmapping and MADV_DONTNEED,
/// and the peak keeps the most there were.
fn resident_count() -> Result<(), &'static str> {
    use super::aspace::{AddressSpace, Fault, Prot};
    fn touch(a: &mut AddressSpace, addr: u64) -> Result<(), &'static str> {
        loop {
            match a.handle_fault(addr, true, false) {
                Fault::Fixed | Fault::FixedReplaced => return Ok(()),
                // A split waits for a shootdown; no CPU runs this space.
                Fault::NeedsFlush => a.flushed = a.removals,
                _ => return Err("fault not fixed"),
            }
        }
    }
    fn check(a: &AddressSpace, now: u64, peak: u64) -> Result<(), &'static str> {
        ensure(a.resident_pages() == a.count_resident_pages(), "count differs from the page tables")?;
        ensure(a.resident_pages() == now, "wrong resident count")?;
        ensure(a.peak_pages() == peak, "wrong peak")
    }
    let mut a = AddressSpace::new().map_err(|_| "no address space")?;
    let base = a.map(None, 64 * PAGE_SIZE, Prot::RW, false).map_err(|_| "map failed")?;
    for i in 0..64 {
        touch(&mut a, base + i * PAGE_SIZE)?;
    }
    check(&a, 64, 64)?;
    let mut b = a.fork().map_err(|_| "fork failed")?;
    check(&b, 64, 64)?;
    for i in 0..8 {
        touch(&mut b, base + i * PAGE_SIZE)?;
    }
    check(&b, 64, 64)?;
    a.unmap(base, 16 * PAGE_SIZE).map_err(|_| "unmap failed")?;
    check(&a, 48, 64)?;
    a.discard(base + 16 * PAGE_SIZE, 16 * PAGE_SIZE).map_err(|_| "discard failed")?;
    check(&a, 32, 64)?;
    for i in 16..20 {
        touch(&mut a, base + i * PAGE_SIZE)?;
    }
    check(&a, 36, 64)?;
    drop(b);
    drop(a);
    Ok(())
}

/// A user page shared by more mappings than 16 bits count (the vDSO's
/// pages in more than 65 535 processes) keeps its count and is freed with
/// the last one only.
fn user_page_many_refs() -> Result<(), &'static str> {
    const REFS: u32 = 70_000;
    let p = frame::UserPage::new().ok_or("no user page")?;
    p.write(0, b"slate");
    let mut shared = Vec::with_capacity(REFS as usize);
    for _ in 0..REFS {
        shared.push(p.share());
    }
    ensure(frame::user_page_refs(shared[0]) == REFS + 1, "count lost past 16 bits")?;
    for &q in &shared {
        frame::put_user_page(q);
    }
    ensure(frame::user_page_refs(shared[0]) == 1 && !p.shared(), "count not back to one")?;
    let mut b = [0; 5];
    p.read(0, &mut b);
    ensure(&b == b"slate", "page freed while still held")
}

/// Scratch memory beyond the heap's largest block: usable, and zeroed for
/// the next user after it is dropped.
fn scratch_memory() -> Result<(), &'static str> {
    let free = frame::stats().free_frames;
    let mut s = super::vmap::Scratch::new(9 << 20).ok_or("no scratch memory")?;
    let pages = (9 << 20) / PAGE_SIZE;
    let m = s.as_mut_slice();
    ensure(m.len() == 9 << 20 && m.iter().all(|&b| b == 0), "not 9 MiB of zeros")?;
    for (i, b) in m.iter_mut().enumerate().step_by(4093) {
        *b = i as u8 | 1;
    }
    ensure(m.iter().enumerate().step_by(4093).all(|(i, &b)| b == i as u8 | 1), "lost writes")?;
    // Other CPUs may free frames meanwhile (seen with 32 of them, the
    // reference PC's shape): a slack far below the 2304 taken.
    ensure(frame::stats().free_frames + pages <= free + 512, "frames not taken")?;
    drop(s);
    // The region's new page tables stay (a few frames); other CPUs may
    // allocate meanwhile, hence the slack.
    ensure(frame::stats().free_frames + 64 >= free, "frames not freed")
}

fn fill(p: PhysAddr, order: usize, tag: u64) {
    let words = (PAGE_SIZE << order) / 8;
    let base = p.to_virt().cast::<u64>();
    for i in (0..words).step_by(61) {
        // SAFETY: The block was allocated by the caller and is mapped in the
        // direct map; `i` stays within it.
        unsafe { base.add(i as usize).write(tag ^ i) };
    }
}

fn check(p: PhysAddr, order: usize, tag: u64) -> bool {
    let words = (PAGE_SIZE << order) / 8;
    let base = p.to_virt().cast::<u64>();
    // SAFETY: As in `fill`.
    (0..words).step_by(61).all(|i| unsafe { base.add(i as usize).read() } == tag ^ i)
}

/// Random allocations and frees leave the free count as it was. Drivers
/// on other CPUs may take or give back frames meanwhile (devices set up
/// at boot): a leak shows every time, so up to three tries.
fn frames_random() -> Result<(), &'static str> {
    for attempt in 1..=3 {
        let before = frame::stats().free_frames;
        frames_random_once()?;
        let after = frame::stats().free_frames;
        if after == before {
            return Ok(());
        }
        crate::log_warn!("mm::frames_random: try {attempt}: {before} free frames before, {after} after");
    }
    Err("free frame count not restored")
}

fn frames_random_once() -> Result<(), &'static str> {
    let mut rng = Rng::new(0xF00D);
    let mut live: Vec<(PhysAddr, usize, u64)> = Vec::with_capacity(4096);
    for i in 0..20_000u64 {
        if live.len() < 4000 && (live.is_empty() || rng.next() % 3 != 0) {
            let order = (rng.next() % 5) as usize;
            let p = frame::alloc(order).ok_or("out of frames")?;
            fill(p, order, i);
            live.push((p, order, i));
        } else {
            let (p, order, tag) = live.swap_remove((rng.next() % live.len() as u64) as usize);
            ensure(check(p, order, tag), "frame contents were overwritten")?;
            frame::free(p, order);
        }
    }
    for (p, order, tag) in live {
        ensure(check(p, order, tag), "frame contents were overwritten")?;
        frame::free(p, order);
    }
    Ok(())
}

fn frames_exhaust() -> Result<(), &'static str> {
    let before = frame::free_blocks();
    // Chain every free block, largest first, through its own first word, so
    // no heap memory is needed while memory is exhausted.
    let mut head: Option<(PhysAddr, usize)> = None;
    let mut count = 0u64;
    for order in (0..=frame::MAX_ORDER).rev() {
        while let Some(p) = frame::alloc(order) {
            let link = head.map_or(0, |(q, o)| q.0 | o as u64);
            // SAFETY: `p` is a block we own, mapped in the direct map.
            unsafe { p.to_virt().cast::<u64>().write(link) };
            head = Some((p, order));
            count += 1;
        }
    }
    let exhausted = frame::stats().free_frames == 0 && frame::alloc(0).is_none();
    while let Some((p, order)) = head {
        // SAFETY: Written above.
        let link = unsafe { p.to_virt().cast::<u64>().read() };
        head = (link != 0).then_some((PhysAddr(link & !(PAGE_SIZE - 1)), (link & 0xF) as usize));
        frame::free(p, order);
    }
    ensure(count > 0 && exhausted, "allocator did not run dry")?;
    ensure(frame::free_blocks() == before, "blocks did not coalesce back to the original state")
}

fn heap_stress() -> Result<(), &'static str> {
    let before = heap::slab_stats().objects_in_use;
    let mut rng = Rng::new(0xBEEF);
    let mut live: Vec<(*mut u8, Layout, u8)> = Vec::with_capacity(3000);
    for i in 0..100_000u32 {
        if live.len() < 2500 && (live.is_empty() || rng.next() % 5 < 3) {
            let size = match rng.next() % 10 {
                0 => 2049 + (rng.next() % 20_000) as usize,
                _ => 1 + (rng.next() % 2048) as usize,
            };
            let align = 1 << (rng.next() % 7);
            let layout = Layout::from_size_align(size, align).unwrap();
            // SAFETY: The layout has non-zero size.
            let p = unsafe { alloc::alloc::alloc(layout) };
            ensure(!p.is_null(), "heap allocation failed")?;
            ensure(p as usize % align == 0, "heap allocation misaligned")?;
            let tag = i as u8;
            // SAFETY: `p` points at `size` bytes we own.
            unsafe { core::ptr::write_bytes(p, tag, size) };
            live.push((p, layout, tag));
        } else {
            let (p, layout, tag) = live.swap_remove((rng.next() % live.len() as u64) as usize);
            // SAFETY: `p` is a live allocation of `layout.size()` bytes.
            let bytes = unsafe { core::slice::from_raw_parts(p, layout.size()) };
            ensure(bytes.iter().all(|&b| b == tag), "heap object was overwritten")?;
            // SAFETY: Allocated above with this layout.
            unsafe { alloc::alloc::dealloc(p, layout) };
        }
    }
    for (p, layout, _) in live.drain(..) {
        // SAFETY: Allocated above with this layout.
        unsafe { alloc::alloc::dealloc(p, layout) };
    }
    drop(live);
    // Other kernel threads allocate meanwhile (a sleeping thread's entry
    // among the sleepers, the stack reaper's every 20 ms): a few objects
    // either way are theirs. A leak here would be thousands.
    let after = heap::slab_stats().objects_in_use;
    ensure(after.abs_diff(before) <= 8, "slab objects leaked")
}

fn heap_collections() -> Result<(), &'static str> {
    let mut v: Vec<u64> = Vec::new();
    for i in 0..200_000 {
        v.push(i * 3);
    }
    ensure(v.iter().enumerate().all(|(i, &x)| x == i as u64 * 3), "Vec contents wrong")?;
    let mut m = BTreeMap::new();
    for i in 0..10_000u32 {
        m.insert(i.wrapping_mul(2_654_435_761), i);
    }
    ensure(m.len() == 10_000, "BTreeMap lost entries")?;
    let b = Box::new([7u8; 3000]);
    ensure(b.iter().all(|&x| x == 7), "Box contents wrong")
}

fn text_read_only() -> Result<(), &'static str> {
    let text = text_read_only as *const () as u64;
    ensure(probe::read_u8(text).is_ok(), "kernel text is not readable")?;
    // SAFETY: The write must fault: kernel text is mapped read-only.
    let f = unsafe { probe::write_u8(text, 0xCC) }.err().ok_or("kernel text is writable")?;
    // #PF error code: P=1 (protection), W/R=1 (write).
    ensure(f.vector == 14 && f.error_code & 0b11 == 0b11, "expected a write protection #PF")?;
    let s: &'static str = "rodata";
    // SAFETY: As above; string literals live in read-only data.
    let f = unsafe { probe::write_u8(s.as_ptr() as u64, 0) }.err().ok_or("rodata is writable")?;
    ensure(f.error_code & 0b11 == 0b11, "expected a write protection #PF on rodata")
}

fn stack_guard() -> Result<(), &'static str> {
    let stack = KernelStack::new().ok_or("no memory for a stack")?;
    let (bottom, top) = (stack.bottom(), stack.top());
    // SAFETY: The stack is ours and unused.
    ensure(unsafe { probe::write_u8(top - 1, 1) }.is_ok(), "stack top not writable")?;
    // SAFETY: As above.
    ensure(unsafe { probe::write_u8(bottom, 1) }.is_ok(), "stack bottom not writable")?;
    let f = probe::read_u8(bottom - 1).err().ok_or("guard page is mapped")?;
    ensure(f.vector == 14 && f.error_code & 1 == 0, "expected a not-present #PF in the guard page")?;
    drop(stack);
    // Freed, it is unmapped (M25): a stale pointer into it faults, and its
    // slot waits before it is used again.
    super::vmap::reap_stacks();
    let f = probe::read_u8(top - 1).err().ok_or("a freed stack is still mapped")?;
    ensure(f.vector == 14 && f.error_code & 1 == 0, "expected a not-present #PF in a freed stack")?;
    let again = KernelStack::new().ok_or("no memory for a stack")?;
    ensure(again.top() != top, "a freed stack slot is reused at once")
}

/// Threads that exit leave no stack mapped behind them.
fn stacks_unmapped() -> Result<(), &'static str> {
    use core::sync::atomic::{AtomicU64, Ordering};
    let at = alloc::sync::Arc::new(AtomicU64::new(0));
    let seen = at.clone();
    let t = crate::sched::spawn("stack-probe", move || {
        let x = 0u8;
        seen.store(&x as *const u8 as u64, Ordering::Relaxed);
    });
    t.join();
    drop(t);
    let addr = at.load(Ordering::Relaxed);
    ensure(super::vmap::in_stack_region(addr), "the thread did not run on a kernel stack")?;
    // The reaper unmaps it within its interval.
    let deadline = crate::time::monotonic_ns() + 2_000_000_000;
    while probe::read_u8(addr).is_ok() {
        ensure(crate::time::monotonic_ns() < deadline, "an exited thread's stack is still mapped after 2 s")?;
        crate::time::sleep_ns(10_000_000);
    }
    Ok(())
}

/// More threads than the slot quarantine, on every CPU, each checking a
/// pattern it writes on its own stack: a reused slot must reach only its
/// new frames (no CPU may keep an old translation of it).
fn stack_slots_reused() -> Result<(), &'static str> {
    use core::sync::atomic::{AtomicU64, Ordering};
    let bad = alloc::sync::Arc::new(AtomicU64::new(0));
    let cpus = crate::sched::cpu_count() as u32;
    for round in 0..25u64 {
        let threads: Vec<_> = (0..100u64)
            .map(|i| {
                let bad = bad.clone();
                crate::sched::spawn_on("slot-reuse", Some((i as u32) % cpus), move || {
                    let mut buf = [0u64; 512];
                    let tag = round << 32 | i;
                    for (j, w) in buf.iter_mut().enumerate() {
                        *w = tag ^ j as u64;
                    }
                    core::hint::black_box(&mut buf);
                    if buf.iter().enumerate().any(|(j, w)| *w != tag ^ j as u64) {
                        bad.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join();
        }
        super::vmap::reap_stacks();
    }
    ensure(bad.load(Ordering::Relaxed) == 0, "a thread's stack changed under it")
}

fn protection_features() -> Result<(), &'static str> {
    let ebx7 = cpu::cpuid(7, 0).1;
    let cr4 = cpu::read_cr4();
    ensure(cpu::read_cr0() & (1 << 16) != 0, "CR0.WP is off")?;
    ensure(ebx7 & (1 << 7) == 0 || cr4 & (1 << 20) != 0, "SMEP supported but off")?;
    ensure(ebx7 & (1 << 20) == 0 || cr4 & (1 << 21) != 0, "SMAP supported but off")?;
    ensure(cpu::read_cr3() & !0xFFF == paging::kernel_root().0, "not running on the kernel page tables")?;
    // The direct map and the page tables agree.
    let x = 0u64;
    let virt = &x as *const u64 as u64;
    let phys = paging::kernel_mapper().translate(virt).ok_or("stack variable not mapped")?;
    ensure(phys.to_virt() as u64 == virt || phys.0 < (1 << 52), "translate gave an impossible address")?;
    let direct = PhysAddr(0x10_0000).to_virt() as u64;
    ensure(paging::kernel_mapper().translate(direct) == Some(PhysAddr(0x10_0000)), "direct map translation wrong")
}
