// SPDX-License-Identifier: MIT OR Apache-2.0

//! Threads and thread-local storage (ADR 0073).
//!
//! Thread-local storage follows the x86-64 psABI's variant II ("ELF
//! Handling For Thread-Local Storage", §3.4.6 and §4.3 for the local-exec
//! model our static programs use): each thread's FS base (its thread
//! pointer) points at a small control block whose first word points to
//! itself, and the program's TLS block (the PT_TLS segment: initialised
//! data, then zeros) sits just below it, at the thread pointer minus the
//! segment's size rounded up to its alignment.
//!
//! A thread is one mapping: a guard page, its stack, its TLS block and
//! its control block. The control block holds the thread-ID word the
//! kernel clears (and wakes) when the thread ends; `join` sleeps on it,
//! then unmaps the thread. A thread nobody joins is unmapped by a later
//! `spawn` once its word reads zero. A panic in any thread ends the whole
//! process, as `panic = "abort"` does for the first one.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use slate_sync::SpinLock;

use crate::sync::{Mutex, futex_wait_tid};
use crate::{Errno, Result, sys};

const PAGE: usize = 4096;
/// The stack a thread gets unless asked otherwise.
pub const DEFAULT_STACK: usize = 1024 * 1024;

/// The thread control block, at the thread pointer.
#[repr(C)]
struct Tcb {
    /// The thread pointer itself (FS:0, psABI).
    this: usize,
    /// The thread's ID while it runs; the kernel zeroes it at the end.
    tid: AtomicU32,
    _pad: u32,
    /// The thread's code (a `Box<Box<dyn FnOnce()>>` as a raw pointer),
    /// taken when it starts.
    start: usize,
    /// Reserved: C compilers keep a stack-protector value at FS:0x28.
    _reserved: [usize; 5],
}

/// The PT_TLS segment: (address, initialised size, total size, alignment).
#[derive(Clone, Copy, Debug, Default)]
struct Image {
    addr: usize,
    filesz: usize,
    memsz: usize,
    align: usize,
}

static IMAGE: SpinLock<Image> = SpinLock::new(Image { addr: 0, filesz: 0, memsz: 0, align: 1 });

/// Program-header type of the TLS segment (System V gABI, "Program
/// Header").
const PT_TLS: u32 = 7;

impl Image {
    /// The TLS block's size below the thread pointer.
    fn offset(&self) -> usize {
        self.memsz.next_multiple_of(self.align)
    }

    /// Room for the block and the control block, and the thread pointer's
    /// alignment.
    fn layout(&self) -> (usize, usize) {
        let align = self.align.max(64);
        (self.offset() + size_of::<Tcb>() + align, align)
    }

    /// Lay out a TLS block and control block in `area` (zeroed memory of
    /// at least `layout().0` bytes); returns the thread pointer.
    ///
    /// # Safety
    ///
    /// `area` must be writable, zeroed and that large.
    unsafe fn install(&self, area: usize) -> *mut Tcb {
        let (_, align) = self.layout();
        let tp = (area + self.offset()).next_multiple_of(align);
        let block = tp - self.offset();
        // SAFETY: `block..tp + size_of::<Tcb>()` lies inside `area` (the
        // caller's size covers the alignment slack); the image is the
        // program's own PT_TLS data.
        unsafe {
            core::ptr::copy_nonoverlapping(self.addr as *const u8, block as *mut u8, self.filesz);
            let tcb = tp as *mut Tcb;
            (*tcb).this = tp;
            tcb
        }
    }
}

fn map(len: usize) -> Result<usize> {
    let flags = if sys::native() { slate_abi::map::PRIVATE | slate_abi::map::ANONYMOUS } else { 0x22 };
    // PROT_READ|PROT_WRITE (mmap(2)); the native values are the same bits.
    crate::syscall!(sys::pick(sys::MMAP, slate_abi::nr::MAP), 0, len, 3, flags, usize::MAX, 0)
}

fn unmap(addr: usize, len: usize) {
    let _ = crate::syscall!(sys::pick(sys::MUNMAP, slate_abi::nr::UNMAP), addr, len);
}

fn set_thread_pointer(tp: usize) -> Result<()> {
    if sys::native() {
        crate::syscall!(slate_abi::nr::SET_TLS as usize, tp).map(|_| ())
    } else {
        // ARCH_SET_FS (arch_prctl(2); musl's `__set_thread_area`).
        crate::syscall!(sys::ARCH_PRCTL, 0x1002, tp).map(|_| ())
    }
}

/// Set up the first thread's TLS from the program headers the kernel
/// described in the auxiliary vector (AT_PHDR, AT_PHNUM). Called by
/// start-up before anything touches a thread-local.
///
/// # Safety
///
/// `phdr` must point to the program's `phnum` program headers.
pub(crate) unsafe fn init_main(phdr: usize, phnum: usize) {
    // Elf64_Phdr: type, flags, offset, vaddr, paddr, filesz, memsz, align.
    let mut img = Image { align: 1, ..Image::default() };
    // Not from PT_PHDR: static position-independent programs may have
    // none (ADR 0092).
    let bias = crate::start::bias();
    let mut tls = None;
    for i in 0..phnum {
        // SAFETY: The caller vouches for the headers (56 bytes each).
        let h = unsafe { core::slice::from_raw_parts((phdr + i * 56) as *const u64, 7) };
        if h[0] as u32 == PT_TLS {
            tls = Some([h[2], h[4], h[5], h[6]]);
        }
    }
    if let Some([vaddr, filesz, memsz, align]) = tls {
        img = Image {
            addr: (vaddr as usize).wrapping_add(bias),
            filesz: filesz as usize,
            memsz: memsz as usize,
            align: (align as usize).max(1),
        };
    }
    *IMAGE.lock() = img;
    let (len, _) = img.layout();
    let Ok(area) = map(len.next_multiple_of(PAGE)) else { return };
    // SAFETY: A fresh zeroed mapping of that size.
    let tcb = unsafe { img.install(area) };
    // SAFETY: `tcb` is the control block just laid out.
    unsafe { (*tcb).tid.store(current_id(), Ordering::Relaxed) };
    let _ = set_thread_pointer(tcb as usize);
}

/// The calling thread's ID.
pub fn current_id() -> u32 {
    crate::syscall!(sys::pick(sys::GETTID, slate_abi::nr::GETTID)).unwrap_or(0) as u32
}

/// Mappings of threads nobody joined: (address, length, control block).
static UNJOINED: SpinLock<Vec<(usize, usize, usize)>> = SpinLock::new(Vec::new());

/// Unmap the unjoined threads that have ended.
fn reap() {
    let mut list = UNJOINED.lock();
    list.retain(|&(addr, len, tcb)| {
        // SAFETY: The mapping stays until it is reaped here.
        let ended = unsafe { (*(tcb as *const Tcb)).tid.load(Ordering::Acquire) } == 0;
        if ended {
            unmap(addr, len);
        }
        !ended
    });
}

/// A thread's start: run its code, then end the thread.
extern "C" fn thread_main(tcb: *mut Tcb) -> ! {
    // SAFETY: `spawn` stored a leaked `Box<Box<dyn FnOnce()>>` here and
    // nothing else takes it.
    let f = unsafe { Box::from_raw((*tcb).start as *mut Box<dyn FnOnce() + Send>) };
    f();
    exit(0)
}

/// End the calling thread (the process ends with its last one).
pub fn exit(status: i32) -> ! {
    loop {
        let _ = crate::syscall!(sys::pick(sys::EXIT, slate_abi::nr::THREAD_EXIT), status);
    }
}

/// Linux's clone(2) for a thread: the child starts on `stack`, where
/// [`spawn`] put the entry point and its argument; it pops them and calls
/// the entry. Registers: flags rdi, stack rsi, parent TID rdx, child TID
/// rcx (moved to r10 for the kernel), TLS r8. Returns the child's ID (or
/// `-errno`) in the parent.
#[unsafe(naked)]
unsafe extern "C" fn linux_clone(flags: usize, stack: usize, ptid: usize, ctid: usize, tls: usize) -> isize {
    core::arch::naked_asm!(
        "mov r10, rcx",
        "mov eax, {nr}",
        "syscall",
        "test rax, rax",
        "jnz 2f",
        "pop rax",
        "pop rdi",
        "xor ebp, ebp",
        "call rax",
        "ud2",
        "2:",
        "ret",
        nr = const sys::CLONE,
    )
}

/// clone(2) flags for a thread (musl `sched.h`, ADR 0009): VM, FS, FILES,
/// SIGHAND, THREAD, SYSVSEM, SETTLS, PARENT_SETTID, CHILD_CLEARTID.
const LINUX_THREAD_FLAGS: usize = 0x100 | 0x200 | 0x400 | 0x800 | 0x10000 | 0x40000 | 0x80000 | 0x100000 | 0x200000;

/// A running thread; [`join`](Self::join) waits for its result. Dropping
/// it detaches the thread.
pub struct JoinHandle<T> {
    map: (usize, usize),
    tcb: *mut Tcb,
    result: Arc<Mutex<Option<T>>>,
}

// SAFETY: The handle only reads the control block's atomic word and owns
// the mapping; the result is behind a lock.
unsafe impl<T: Send> Send for JoinHandle<T> {}

impl<T> core::fmt::Debug for JoinHandle<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "JoinHandle({})", self.id())
    }
}

impl<T> JoinHandle<T> {
    /// The thread's ID (0 once it has ended).
    pub fn id(&self) -> u32 {
        // SAFETY: The mapping lives as long as the handle.
        unsafe { (*self.tcb).tid.load(Ordering::Relaxed) }
    }

    /// Wait for the thread to end; its result.
    pub fn join(self) -> T {
        // The thread stored a result before it ended, unless it left
        // through `exit` (a panic would have ended the process).
        self.finish().unwrap_or_else(|| unreachable!())
    }

    /// Wait for the thread to end; its result, or None if it left
    /// through [`exit`].
    pub fn finish(self) -> Option<T> {
        self.wait();
        let v = self.result.lock().take();
        let map = self.map;
        core::mem::forget(self);
        unmap(map.0, map.1);
        v
    }

    /// Sleep until the thread's ID word reads zero.
    pub fn wait(&self) {
        // SAFETY: As in `id`.
        let word = unsafe { &(*self.tcb).tid };
        loop {
            let t = word.load(Ordering::Acquire);
            if t == 0 {
                return;
            }
            let _ = futex_wait_tid(word, t);
        }
    }
}

impl<T> Drop for JoinHandle<T> {
    fn drop(&mut self) {
        UNJOINED.lock().push((self.map.0, self.map.1, self.tcb as usize));
    }
}

/// Start a thread running `f`, with a stack of [`DEFAULT_STACK`] bytes.
pub fn spawn<F, T>(f: F) -> Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    spawn_with(DEFAULT_STACK, f)
}

/// Start a thread with a stack of (at least) `stack` bytes.
pub fn spawn_with<F, T>(stack: usize, f: F) -> Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    reap();
    let img = *IMAGE.lock();
    let stack = stack.max(16 * 1024).next_multiple_of(PAGE);
    let (tls_len, _) = img.layout();
    let len = PAGE + stack + tls_len.next_multiple_of(PAGE);
    let base = map(len)?;
    // The lowest page is the guard: a stack overflow faults there.
    let _ = crate::syscall!(sys::pick(sys::MPROTECT, slate_abi::nr::PROTECT), base, PAGE, 0);
    let top = base + PAGE + stack;
    // SAFETY: The area above the stack is fresh, zeroed and `tls_len`
    // bytes or more.
    let tcb = unsafe { img.install(top) };
    let result = Arc::new(Mutex::new(None));
    let slot = result.clone();
    let code: Box<dyn FnOnce() + Send> = Box::new(move || {
        let v = f();
        *slot.lock() = Some(v);
    });
    // SAFETY: `tcb` is inside the new mapping; the thread takes `start`.
    unsafe { (*tcb).start = Box::into_raw(Box::new(code)) as usize };
    let tid_word = tcb as usize + core::mem::offset_of!(Tcb, tid);
    let r = if sys::native() {
        crate::syscall!(
            slate_abi::nr::THREAD_START as usize,
            thread_main as *const () as usize,
            tcb,
            top,
            tcb,
            tid_word
        )
    } else {
        // The child pops the entry point, then its argument.
        // SAFETY: The two words below `top` are on the new stack.
        unsafe {
            *((top - 16) as *mut usize) = thread_main as *const () as usize;
            *((top - 8) as *mut usize) = tcb as usize;
        }
        // SAFETY: A thread clone onto the new stack; the child runs
        // `thread_main` and never returns into this frame.
        let r = unsafe { linux_clone(LINUX_THREAD_FLAGS, top - 16, tid_word, tid_word, tcb as usize) };
        if r < 0 { Err(Errno(-r as i32)) } else { Ok(r as usize) }
    };
    if let Err(e) = r {
        // SAFETY: The thread never started, so the code is still ours.
        drop(unsafe { Box::from_raw((*tcb).start as *mut Box<dyn FnOnce() + Send>) });
        unmap(base, len);
        return Err(e);
    }
    Ok(JoinHandle { map: (base, len), tcb, result })
}
