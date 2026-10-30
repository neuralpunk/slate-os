// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Linux x86-64 system call personality.
//!
//! Calling convention (System V AMD64 psABI, appendix A.2, and syscall(2)):
//! number in rax, arguments in rdi, rsi, rdx, r10, r8, r9, result in rax as
//! a value or `-errno`. Coverage is tracked in docs/linux-abi.md.

pub mod bpf;
pub(crate) mod cred;
pub mod errno;
pub(crate) mod fs;
pub(crate) mod io;
pub mod ioctl;
pub(crate) mod mem;
pub(crate) mod net;
pub mod nr;
pub(crate) mod process;
pub(crate) mod time;
pub mod trace;
pub(crate) mod xattr;

use core::sync::atomic::{AtomicU64, Ordering};

use errno::{ENOSYS, Errno};

use crate::arch::trap::TrapFrame;
use crate::log_warn;

/// System call arguments.
#[derive(Clone, Copy, Debug)]
pub struct Args(pub [u64; 6]);

impl Args {
    pub fn fd(&self, i: usize) -> i32 {
        self.0[i] as i32
    }
}

pub type Result = core::result::Result<u64, Errno>;

/// Unimplemented numbers already reported (one bit each, 0..512).
static REPORTED: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];

fn unimplemented(nr: u64) -> Result {
    let (word, bit) = ((nr / 64) as usize, nr % 64);
    let first = word >= REPORTED.len() || REPORTED[word].fetch_or(1 << bit, Ordering::Relaxed) & (1 << bit) == 0;
    if first {
        let pid = crate::proc::current().map_or(0, |p| p.pid);
        log_warn!("pid {pid}: unimplemented syscall {nr} ({})", nr::name(nr).unwrap_or("unknown"));
    }
    Err(ENOSYS)
}

/// Run the system call described by `frame` and store its result.
pub fn syscall(frame: &mut TrapFrame) {
    let nr = frame.rax;
    let a = Args([frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9]);
    let traced = trace::wanted();
    // Not held across the call: exit and a successful execve never return.
    {
        let t = crate::sched::current();
        t.syscall_arg.store(a.0[0], core::sync::atomic::Ordering::Relaxed);
        t.syscall.store(nr + 1, core::sync::atomic::Ordering::Relaxed);
    }
    let r = dispatch(nr, a, frame, traced);
    crate::sched::current().syscall.store(0, core::sync::atomic::Ordering::Relaxed);
    if let Some(r) = r {
        frame.rax = match r {
            Ok(v) => v,
            Err(e) => (-(e.0 as i64)) as u64,
        };
    }
}

/// Run system call `nr`; `None` when the seccomp check already set the
/// result in `frame`.
fn dispatch(nr: u64, a: Args, frame: &mut TrapFrame, traced: bool) -> Option<Result> {
    if crate::proc::seccomp::IN_USE.load(core::sync::atomic::Ordering::Acquire)
        && let Some(r) = process::seccomp_check(nr, &a, frame.rip)
    {
        if traced {
            trace::log(nr, &a, &r);
        }
        frame.rax = match r {
            Ok(v) => v,
            Err(e) => (-(e.0 as i64)) as u64,
        };
        return None;
    }
    let r = match nr {
        nr::READ => io::read(a),
        nr::WRITE => io::write(a),
        nr::OPEN => fs::open(a),
        nr::OPENAT => fs::openat(a),
        nr::OPENAT2 => fs::openat2(a),
        nr::NAME_TO_HANDLE_AT => fs::name_to_handle_at(a),
        nr::OPEN_BY_HANDLE_AT => fs::open_by_handle_at(a),
        nr::CREAT => fs::creat(a),
        nr::CLOSE => io::close(a),
        nr::READV => io::readv(a),
        nr::WRITEV => io::writev(a),
        nr::IOCTL => io::ioctl(a),
        nr::SENDFILE => io::sendfile(a),
        nr::SPLICE => io::splice(a),
        nr::EVENTFD => fs::eventfd(a),
        nr::EVENTFD2 => fs::eventfd2(a),
        nr::INOTIFY_INIT => fs::inotify_init(a),
        nr::INOTIFY_INIT1 => fs::inotify_init1(a),
        nr::INOTIFY_ADD_WATCH => fs::inotify_add_watch(a),
        nr::INOTIFY_RM_WATCH => fs::inotify_rm_watch(a),
        nr::TIMERFD_CREATE => fs::timerfd_create(a),
        nr::TIMERFD_SETTIME => fs::timerfd_settime(a),
        nr::TIMERFD_GETTIME => fs::timerfd_gettime(a),
        nr::SIGNALFD => fs::signalfd(a),
        nr::SIGNALFD4 => fs::signalfd4(a),
        nr::EPOLL_CREATE => fs::epoll_create(a),
        nr::EPOLL_CREATE1 => fs::epoll_create1(a),
        nr::EPOLL_CTL => fs::epoll_ctl(a),
        nr::EPOLL_WAIT => fs::epoll_wait(a),
        nr::EPOLL_PWAIT => fs::epoll_pwait(a),
        nr::EPOLL_PWAIT2 => fs::epoll_pwait2(a),
        nr::ALARM => process::alarm(a),
        nr::GETRUSAGE => process::getrusage(a),
        nr::SETITIMER => process::setitimer(a),
        nr::GETITIMER => process::getitimer(a),
        nr::LSEEK => fs::lseek(a),
        nr::PREAD64 => io::pread64(a),
        nr::PWRITE64 => io::pwrite64(a),
        nr::GETDENTS64 => fs::getdents64(a),
        nr::STAT => fs::stat(a),
        nr::LSTAT => fs::lstat(a),
        nr::FSTAT => fs::fstat(a),
        nr::NEWFSTATAT => fs::newfstatat(a),
        nr::STATX => fs::statx(a),
        nr::ACCESS => fs::access(a),
        nr::FACCESSAT => fs::faccessat(a),
        nr::FACCESSAT2 => fs::faccessat2(a),
        nr::MKDIR => fs::mkdir(a),
        nr::MKDIRAT => fs::mkdirat(a),
        nr::MKNODAT => fs::mknodat(a),
        nr::MKNOD => fs::mknod(a),
        nr::UNLINK => fs::unlink(a),
        nr::UNLINKAT => fs::unlinkat(a),
        nr::RMDIR => fs::rmdir(a),
        nr::RENAME => fs::rename(a),
        nr::RENAMEAT => fs::renameat(a),
        nr::RENAMEAT2 => fs::renameat2(a),
        nr::SYMLINK => fs::symlink(a),
        nr::SYMLINKAT => fs::symlinkat(a),
        nr::LINK => fs::link(a),
        nr::LINKAT => fs::linkat(a),
        nr::READLINK => fs::readlink(a),
        nr::READLINKAT => fs::readlinkat(a),
        nr::CHDIR => fs::chdir(a),
        nr::FCHDIR => fs::fchdir(a),
        nr::GETCWD => fs::getcwd(a),
        nr::CHMOD => fs::chmod(a),
        nr::FCHMOD => fs::fchmod(a),
        nr::FCHMODAT => fs::fchmodat(a),
        nr::FCHMODAT2 => fs::fchmodat2(a),
        nr::CHOWN => fs::chown(a),
        nr::FCHOWN => fs::fchown(a),
        nr::LCHOWN => fs::lchown(a),
        nr::FCHOWNAT => fs::fchownat(a),
        nr::UMASK => fs::umask(a),
        nr::TRUNCATE => fs::truncate(a),
        nr::FTRUNCATE => fs::ftruncate(a),
        nr::UTIMENSAT => fs::utimensat(a),
        nr::DUP => fs::dup(a),
        nr::DUP2 => fs::dup2(a),
        nr::DUP3 => fs::dup3(a),
        nr::FCNTL => fs::fcntl(a),
        nr::PIPE => fs::pipe(a),
        nr::PIPE2 => fs::pipe2(a),
        nr::FSYNC | nr::FDATASYNC => fs::fsync(a),
        nr::SYNC => fs::sync(a),
        nr::SYNCFS => fs::syncfs(a),
        nr::SYNC_FILE_RANGE => fs::sync_file_range(a),
        nr::FLOCK => fs::flock(a),
        nr::POLL => fs::poll(a),
        nr::PPOLL => fs::ppoll(a),
        nr::SELECT => fs::select(a),
        nr::PSELECT6 => fs::pselect6(a),
        nr::MOUNT => fs::mount(a),
        nr::UMOUNT2 => fs::umount2(a),
        nr::STATFS => fs::statfs(a),
        nr::FSTATFS => fs::fstatfs(a),

        nr::MMAP => mem::mmap(a),
        nr::MPROTECT => mem::mprotect(a),
        nr::MUNMAP => mem::munmap(a),
        nr::BRK => mem::brk(a),
        nr::MADVISE => mem::madvise(a),
        nr::MLOCK | nr::MUNLOCK => mem::mlock(a, None),
        nr::MLOCK2 => mem::mlock(a, Some(a.0[2])),
        nr::MLOCKALL => mem::mlockall(a),
        nr::MUNLOCKALL => Ok(0),
        nr::COPY_FILE_RANGE => io::copy_file_range(a),
        nr::MINCORE => mem::mincore(a),
        nr::MSYNC => mem::msync(a),

        nr::FORK => process::fork(frame),
        nr::VFORK => process::vfork(frame),
        nr::CLONE => process::clone(a, frame),
        nr::EXECVE => process::execve(a, frame),
        nr::EXIT => process::exit(a),
        nr::EXIT_GROUP => process::exit_group(a),
        nr::CLONE3 => process::clone3(a, frame),
        nr::FUTEX => process::futex(a),
        nr::CHROOT => process::chroot(a),
        nr::MREMAP => mem::mremap(a),
        nr::WAIT4 => process::wait4(a),
        nr::KILL => process::kill(a),
        nr::TGKILL => process::tgkill(a),
        nr::RT_SIGQUEUEINFO => process::rt_sigqueueinfo(a),
        nr::RT_TGSIGQUEUEINFO => process::rt_tgsigqueueinfo(a),
        nr::RT_SIGTIMEDWAIT => process::rt_sigtimedwait(a),
        nr::TKILL => process::tkill(a),
        nr::GETPID => process::getpid(),
        nr::GETTID => process::gettid(),
        nr::GETPPID => process::getppid(),
        nr::GETPGRP => process::getpgid(Args([0; 6])),
        nr::GETPGID => process::getpgid(a),
        nr::SETPGID => process::setpgid(a),
        nr::SETSID => process::setsid(),
        nr::GETSID => process::getsid(a),
        nr::SYSLOG => process::syslog(a),
        nr::GETUID => cred::getuid(),
        nr::GETEUID => cred::geteuid(),
        nr::GETGID => cred::getgid(),
        nr::GETEGID => cred::getegid(),
        nr::SETUID => cred::setuid(a),
        nr::SETGID => cred::setgid(a),
        nr::SETREUID => cred::setreuid(a),
        nr::SETREGID => cred::setregid(a),
        nr::SETRESUID => cred::setresuid(a),
        nr::SETRESGID => cred::setresgid(a),
        nr::SETFSUID => cred::setfsuid(a),
        nr::SETFSGID => cred::setfsgid(a),
        nr::GETRESUID => cred::getresuid(a),
        nr::GETRESGID => cred::getresgid(a),
        nr::GETGROUPS => cred::getgroups(a),
        nr::SETGROUPS => cred::setgroups(a),
        nr::CAPGET => cred::capget(a),
        nr::CAPSET => cred::capset(a),
        nr::SET_TID_ADDRESS => process::set_tid_address(a),
        nr::ARCH_PRCTL => process::arch_prctl(a),
        nr::PRCTL => process::prctl(a),
        nr::UNAME => process::uname(a),
        nr::PERSONALITY => process::personality(a),
        nr::SETHOSTNAME => process::sethostname(a),
        nr::MEMFD_CREATE => fs::memfd_create(a),
        nr::CLOSE_RANGE => process::close_range(a),
        nr::PIDFD_OPEN => process::pidfd_open(a),
        nr::PIDFD_SEND_SIGNAL => process::pidfd_send_signal(a),
        nr::WAITID => process::waitid(a),
        nr::SECCOMP => process::seccomp(a.0[0], a.0[1], a.0[2]),
        nr::BPF => bpf::bpf(a),
        nr::FALLOCATE => fs::fallocate(a),
        nr::EXECVEAT => process::execveat(a, frame),
        nr::MEMBARRIER => process::membarrier(a),
        nr::SETXATTR => xattr::setxattr(a),
        nr::LSETXATTR => xattr::lsetxattr(a),
        nr::FSETXATTR => xattr::fsetxattr(a),
        nr::GETXATTR => xattr::getxattr(a),
        nr::LGETXATTR => xattr::lgetxattr(a),
        nr::FGETXATTR => xattr::fgetxattr(a),
        nr::LISTXATTR => xattr::listxattr(a),
        nr::LLISTXATTR => xattr::llistxattr(a),
        nr::FLISTXATTR => xattr::flistxattr(a),
        nr::REMOVEXATTR => xattr::removexattr(a),
        nr::LREMOVEXATTR => xattr::lremovexattr(a),
        nr::FREMOVEXATTR => xattr::fremovexattr(a),
        nr::UNSHARE => process::unshare(a),
        nr::SETNS => process::setns(a),
        nr::PIVOT_ROOT => fs::pivot_root(a),
        nr::PRLIMIT64 => process::prlimit64(a),
        nr::GETRLIMIT => process::prlimit64(Args([0, a.0[0], 0, a.0[1], 0, 0])),
        nr::SETRLIMIT => process::setrlimit(a),
        nr::SCHED_YIELD => {
            crate::sched::yield_now();
            Ok(0)
        }
        nr::SCHED_GETAFFINITY => process::sched_getaffinity(a),
        nr::SCHED_SETAFFINITY => process::sched_setaffinity(a),
        nr::GET_MEMPOLICY => process::get_mempolicy(a),
        nr::SET_MEMPOLICY | nr::MBIND => process::set_mempolicy(a),
        nr::GETPRIORITY => process::getpriority(a),
        nr::SETPRIORITY => process::setpriority(a),
        nr::SCHED_GET_PRIORITY_MAX => process::sched_priority_range(a.0[0], true),
        nr::SCHED_GET_PRIORITY_MIN => process::sched_priority_range(a.0[0], false),
        nr::SCHED_GETSCHEDULER => process::sched_getscheduler(a),
        nr::SCHED_GETPARAM => process::sched_getparam(a),
        nr::SCHED_SETSCHEDULER => process::sched_setscheduler(a.0[0], Some(a.0[1]), a.0[2]),
        nr::SCHED_SETPARAM => process::sched_setscheduler(a.0[0], None, a.0[1]),
        nr::SCHED_RR_GET_INTERVAL => process::sched_rr_get_interval(a),
        // posix_fadvise(2): advice only; Slate's page cache doesn't use it.
        nr::FADVISE64 => {
            crate::proc::current().ok_or(errno::ESRCH).and_then(|p| p.files.lock().get(a.fd(0)).map(|_| 0))
        }
        // readahead(2): likewise a hint.
        nr::READAHEAD => {
            crate::proc::current().ok_or(errno::ESRCH).and_then(|p| p.files.lock().get(a.fd(0)).map(|_| 0))
        }
        nr::GETRANDOM => process::getrandom(a),
        nr::SYSINFO => process::sysinfo(a),
        nr::TIMES => process::times(a),
        nr::REBOOT => process::reboot(a),
        nr::SET_ROBUST_LIST => process::set_robust_list(a),
        nr::RSEQ => process::rseq(a),
        nr::IOPRIO_GET => process::ioprio_get(a),
        nr::IOPRIO_SET => process::ioprio_set(a),
        nr::GET_ROBUST_LIST => process::get_robust_list(a),

        nr::RT_SIGACTION => process::rt_sigaction(a),
        nr::RT_SIGPROCMASK => process::rt_sigprocmask(a),
        nr::RT_SIGRETURN => process::rt_sigreturn(frame),
        nr::RT_SIGSUSPEND => process::rt_sigsuspend(a),
        nr::RT_SIGPENDING => process::rt_sigpending(a),
        nr::SIGALTSTACK => crate::proc::signal::sigaltstack(a.0[0], a.0[1], frame.rsp).map(|()| 0),
        nr::PAUSE => process::pause(),

        nr::CLOCK_GETTIME => time::clock_gettime(a),
        nr::CLOCK_SETTIME => time::clock_settime(a),
        nr::ADJTIMEX => time::adjtimex(a),
        nr::CLOCK_ADJTIME => time::clock_adjtime(a),
        nr::SETTIMEOFDAY => time::settimeofday(a),
        nr::CLOCK_GETRES => time::clock_getres(a),
        nr::GETTIMEOFDAY => time::gettimeofday(a),
        nr::TIME => time::time(a),
        nr::SOCKET => net::socket(a),
        nr::SOCKETPAIR => net::socketpair(a),
        nr::BIND => net::bind(a),
        nr::LISTEN => net::listen(a),
        nr::ACCEPT => net::accept(a),
        nr::ACCEPT4 => net::accept4(a),
        nr::CONNECT => net::connect(a),
        nr::GETSOCKNAME => net::getsockname(a),
        nr::GETPEERNAME => net::getpeername(a),
        nr::SENDTO => net::sendto(a),
        nr::RECVFROM => net::recvfrom(a),
        nr::SENDMSG => net::sendmsg(a),
        nr::RECVMSG => net::recvmsg(a),
        nr::RECVMMSG => net::recvmmsg(a),
        nr::SENDMMSG => net::sendmmsg(a),
        nr::SETSOCKOPT => net::setsockopt(a),
        nr::GETSOCKOPT => net::getsockopt(a),
        nr::SHUTDOWN => net::shutdown(a),
        nr::GETCPU => time::getcpu(a),
        nr::NANOSLEEP => time::nanosleep(a),
        nr::CLOCK_NANOSLEEP => time::clock_nanosleep(a),

        _ => unimplemented(nr),
    };
    // What a Linux box's programs are refused is logged (ADR 0183).
    if let Err(e) = &r
        && (*e == errno::EPERM || *e == errno::EACCES)
    {
        crate::proc::note_box_refusal(nr::name(nr).unwrap_or("?"), *e);
    }
    if traced {
        trace::log(nr, &a, &r);
    }
    Some(r)
}
