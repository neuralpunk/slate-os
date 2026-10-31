// SPDX-License-Identifier: MIT OR Apache-2.0

//! In-kernel tests that run user programs (built from `tests/user`).

use alloc::vec::Vec;

use super::{spawn, wait_status_exited, wait_status_signaled};
use crate::ktest::{Test, ensure};

pub const TESTS: &[Test] = &[
    Test { name: "user::hello_static", run: hello },
    Test { name: "user::hello_static_pie", run: hello_pie },
    Test { name: "user::aslr", run: aslr },
    Test { name: "user::syscalls", run: syscalls },
    Test { name: "user::resolve", run: resolve },
    Test { name: "user::rseq", run: rseq },
    Test { name: "user::native_abi", run: native_abi },
    Test { name: "user::drm", run: drm },
    Test { name: "user::native_libc", run: native_libc },
    Test { name: "user::slate_mode", run: slate_mode },
    Test { name: "user::segfault_kills", run: segfault },
    Test { name: "user::fork_threads", run: fork_threads },
    Test { name: "user::malloc_fork", run: malloc_fork },
    Test { name: "user::render_pool", run: render_pool },
    Test { name: "user::cow_stale", run: cow_stale },
    Test { name: "user::fpu_state_per_thread", run: fpu },
    Test { name: "user::random_self_test", run: random },
    Test { name: "user::procs", run: procs },
    Test { name: "user::creds", run: creds },
    Test { name: "user::errnos", run: errnos },
    Test { name: "user::siginfo", run: siginfo },
    Test { name: "user::rusage", run: rusage },
    Test { name: "user::memfd", run: memfd },
    Test { name: "user::threadproc", run: threadproc },
    Test { name: "user::login", run: login },
    Test { name: "user::accounts", run: accounts },
    Test { name: "user::chalk", run: chalk },
    Test { name: "user::archives", run: archives },
    Test { name: "user::seatd", run: seat },
    Test { name: "user::init", run: init },
    Test { name: "user::tui", run: tui },
    Test { name: "user::shell_script", run: shell_script },
    Test { name: "user::pty_job_control", run: pty },
    Test { name: "user::threads", run: threads },
    Test { name: "user::teardown_race", run: teardown },
    Test { name: "user::events", run: events },
    Test { name: "user::block", run: block },
    Test { name: "user::alpine_dynamic", run: alpine },
    Test { name: "user::linux_runtime", run: linux_runtime },
    Test { name: "user::ext4", run: ext4 },
    Test { name: "user::net", run: net },
    Test { name: "user::tcp", run: tcp },
    Test { name: "user::unix", run: unix },
    Test { name: "user::uevent", run: uevent },
    Test { name: "user::vt", run: vt },
    Test { name: "user::rtnl", run: rtnl },
    Test { name: "user::sockopts", run: sockopts },
    Test { name: "user::nftables", run: nftables },
    Test { name: "user::links", run: links },
    Test { name: "user::firewall", run: firewall },
    Test { name: "user::inbound", run: inbound },
    Test { name: "user::net6", run: net6 },
    Test { name: "user::net_tools", run: net_tools },
    Test { name: "user::compat", run: compat },
    Test { name: "user::quarry", run: quarry },
    Test { name: "user::slatefs", run: slatefs },
    Test { name: "user::crypt", run: crypt },
    Test { name: "user::discard", run: discard },
    Test { name: "user::containers", run: containers },
    Test { name: "user::disks", run: disks },
    Test { name: "user::locks", run: locks },
    Test { name: "user::clock", run: clock },
    Test { name: "user::resources", run: resources },
    Test { name: "user::churn", run: churn },
    Test { name: "user::ltp", run: ltp },
];

fn churn() -> Result<(), &'static str> {
    ensure(run("churn", &[b"churn"])? == wait_status_exited(0), "process churn leaked memory")
}

/// The LTP subset (ADR 0047), run by tests/ltp/run.sh.
fn ltp() -> Result<(), &'static str> {
    ensure(sh(b"/test/ltp.sh")? == wait_status_exited(0), "LTP tests failed")
}

fn resources() -> Result<(), &'static str> {
    ensure(run("resources", &[b"resources"])? == wait_status_exited(0), "resource control checks failed")
}

fn clock() -> Result<(), &'static str> {
    ensure(run("clock", &[b"clock"])? == wait_status_exited(0), "clock setting checks failed")
}

fn locks() -> Result<(), &'static str> {
    ensure(run("locks", &[b"locks"])? == wait_status_exited(0), "file lock checks failed")
}

fn disks() -> Result<(), &'static str> {
    ensure(run("disks", &[b"disks"])? == wait_status_exited(0), "AHCI/NVMe disk checks failed")
}

fn containers() -> Result<(), &'static str> {
    ensure(run("containers", &[b"containers"])? == wait_status_exited(0), "container (namespace/cgroup) checks failed")
}

fn slatefs() -> Result<(), &'static str> {
    ensure(sh(b"/test/slatefs.sh")? == wait_status_exited(0), "SlateFS checks failed")
}

fn crypt() -> Result<(), &'static str> {
    ensure(sh(b"/test/crypt.sh")? == wait_status_exited(0), "slate-crypt checks failed")
}

fn discard() -> Result<(), &'static str> {
    ensure(sh(b"/test/discard.sh")? == wait_status_exited(0), "discard (TRIM) checks failed")
}

fn quarry() -> Result<(), &'static str> {
    ensure(sh(b"/test/quarry.sh")? == wait_status_exited(0), "quarry checks failed")
}

fn compat() -> Result<(), &'static str> {
    ensure(run("compat", &[b"compat"])? == wait_status_exited(0), "compatibility checks (M12) failed")
}

fn block() -> Result<(), &'static str> {
    ensure(run("block", &[b"block"])? == wait_status_exited(0), "block device checks failed")
}

fn events() -> Result<(), &'static str> {
    ensure(run("events", &[b"events"])? == wait_status_exited(0), "event file checks failed")
}

fn threads() -> Result<(), &'static str> {
    ensure(run("threads", &[b"threads"])? == wait_status_exited(0), "pthread checks failed")
}

/// tests/user/teardown.c: multithreaded processes exit and exec while
/// their threads still run elsewhere; page tables must outlive every CPU
/// using them.
fn teardown() -> Result<(), &'static str> {
    let before = crate::sched::root_waits();
    let status = run("teardown", &[b"teardown", b"300"])?;
    crate::log_info!("teardown: {} teardowns waited for another CPU", crate::sched::root_waits() - before);
    ensure(status == wait_status_exited(0), "teardown stress failed")
}

fn pty() -> Result<(), &'static str> {
    ensure(run("pty", &[b"pty"])? == wait_status_exited(0), "pty/job control checks failed")
}

fn errnos() -> Result<(), &'static str> {
    ensure(run("errnos", &[b"errnos"])? == wait_status_exited(0), "error numbers differ from Linux's")
}

fn siginfo() -> Result<(), &'static str> {
    ensure(run("siginfo", &[b"siginfo"])? == wait_status_exited(0), "siginfo differs from Linux's")
}

fn rusage() -> Result<(), &'static str> {
    ensure(run("rusage", &[b"rusage"])? == wait_status_exited(0), "getrusage differs from Linux's")
}

fn threadproc() -> Result<(), &'static str> {
    ensure(run("threadproc", &[b"threadproc"])? == wait_status_exited(0), "threads in /proc or ps differ from Linux's")
}

fn memfd() -> Result<(), &'static str> {
    ensure(run("memfd", &[b"memfd"])? == wait_status_exited(0), "memfd seals or pidfd signals differ from Linux's")
}

fn creds() -> Result<(), &'static str> {
    ensure(run("creds", &[b"creds"])? == wait_status_exited(0), "credential and permission checks failed")
}

fn tui() -> Result<(), &'static str> {
    ensure(run("tui", &[b"tui"])? == wait_status_exited(0), "etch/less checks failed")
}

fn init() -> Result<(), &'static str> {
    ensure(sh(b"/test/init.sh")? == wait_status_exited(0), "slinit checks failed")
}

fn login() -> Result<(), &'static str> {
    ensure(sh(b"/test/login.sh")? == wait_status_exited(0), "login/su/passwd checks failed")
}

fn chalk() -> Result<(), &'static str> {
    ensure(sh(b"/test/chalk.sh")? == wait_status_exited(0), "chalk checks failed")
}

fn archives() -> Result<(), &'static str> {
    ensure(sh(b"/test/archives.sh")? == wait_status_exited(0), "compressor and tar checks failed")
}

fn accounts() -> Result<(), &'static str> {
    ensure(sh(b"/test/accounts.sh")? == wait_status_exited(0), "account tool checks failed")
}

fn seat() -> Result<(), &'static str> {
    ensure(sh(b"/test/seat.sh")? == wait_status_exited(0), "seatd checks failed")
}

fn procs() -> Result<(), &'static str> {
    ensure(run("procs", &[b"procs"])? == wait_status_exited(0), "process/signal/file checks failed")
}

fn sh(script: &[u8]) -> Result<i32, &'static str> {
    let p = spawn("/bin/sh", &[b"sh", script], &[b"PATH=/bin:/sbin:/usr/bin:/usr/sbin"])
        .map_err(|_| "cannot start /bin/sh")?;
    let status = p.wait();
    super::reap(&p);
    Ok(status)
}

fn shell_script() -> Result<(), &'static str> {
    ensure(sh(b"/test/basics.sh")? == wait_status_exited(0), "shell script checks failed")
}

fn alpine() -> Result<(), &'static str> {
    ensure(sh(b"/test/alpine.sh")? == wait_status_exited(0), "Alpine (dynamic linking) checks failed")
}

/// tests/shell/linuxrt.sh: entering a Linux runtime, and its budget
/// (M31 phase 1).
fn linux_runtime() -> Result<(), &'static str> {
    ensure(sh(b"/test/linuxrt.sh")? == wait_status_exited(0), "Linux runtime checks failed")
}

fn net() -> Result<(), &'static str> {
    ensure(run("net", &[b"net"])? == wait_status_exited(0), "network checks failed")
}

fn net6() -> Result<(), &'static str> {
    ensure(run("net6", &[b"net6"])? == wait_status_exited(0), "IPv6 checks failed")
}

fn rtnl() -> Result<(), &'static str> {
    ensure(run("rtnl", &[b"rtnl"])? == wait_status_exited(0), "route netlink checks failed")
}

/// tests/user/nftables.c: the firewall over nf_tables' netlink (ADR 0129).
fn nftables() -> Result<(), &'static str> {
    ensure(run("nftables", &[b"nftables"])? == wait_status_exited(0), "nf_tables checks failed")
}

/// tests/user/inbound.c: the default inbound firewall seen from another
/// namespace (ADR 0134).
fn inbound() -> Result<(), &'static str> {
    ensure(run("inbound", &[b"inbound"])? == wait_status_exited(0), "inbound firewall checks failed")
}

/// tests/shell/firewall.sh: slate-firewall and the default inbound
/// firewall (ADR 0134).
fn firewall() -> Result<(), &'static str> {
    ensure(sh(b"/test/firewall.sh")? == wait_status_exited(0), "firewall checks failed")
}

/// tests/user/links.c: veth pairs, bridges and forwarding between network
/// namespaces (ADR 0131).
fn links() -> Result<(), &'static str> {
    ensure(run("links", &[b"links"])? == wait_status_exited(0), "interface checks failed")
}

/// tests/user/sockopts.c: socket options done, accepted or refused (ADR 0077).
fn sockopts() -> Result<(), &'static str> {
    ensure(run("sockopts", &[b"sockopts"])? == wait_status_exited(0), "socket option checks failed")
}

fn unix() -> Result<(), &'static str> {
    ensure(run("unix", &[b"unix"])? == wait_status_exited(0), "AF_UNIX/netlink checks failed")
}

/// tests/user/uevent.c: uevent sockets keep to their network namespace
/// (ADR 0185).
fn uevent() -> Result<(), &'static str> {
    ensure(run("uevent", &[b"uevent", b"check"])? == wait_status_exited(0), "uevent namespace checks failed")
}

/// tests/user/vt.c: the virtual consoles' ioctls and switching (ADR 0185).
fn vt() -> Result<(), &'static str> {
    ensure(run("vt", &[b"vt"])? == wait_status_exited(0), "virtual console checks failed")
}

fn tcp() -> Result<(), &'static str> {
    ensure(run("tcp", &[b"tcp"])? == wait_status_exited(0), "TCP checks failed")
}

fn net_tools() -> Result<(), &'static str> {
    ensure(sh(b"/test/net.sh")? == wait_status_exited(0), "BusyBox network tool checks failed")
}

fn ext4() -> Result<(), &'static str> {
    ensure(sh(b"/test/ext4.sh")? == wait_status_exited(0), "ext4 checks failed")
}

fn path(name: &str) -> alloc::string::String {
    alloc::format!("/test/{name}")
}

fn run(name: &str, argv: &[&[u8]]) -> Result<i32, &'static str> {
    let p = spawn(&path(name), argv, &[b"SLATE=1"]).map_err(|_| "spawn failed")?;
    let status = p.wait();
    super::reap(&p);
    Ok(status)
}

fn hello() -> Result<(), &'static str> {
    ensure(run("hello", &[b"hello"])? == wait_status_exited(0), "hello did not exit with 0")
}

fn hello_pie() -> Result<(), &'static str> {
    ensure(run("hello-pie", &[b"hello-pie"])? == wait_status_exited(0), "static-pie hello did not exit with 0")
}

/// tests/user/aslr.c: the layout's entropy, measured over 256 runs (ADR
/// 0092; its `aslr:` lines report the bits).
fn aslr() -> Result<(), &'static str> {
    ensure(run("aslr-pie", &[b"/test/aslr-pie"])? == wait_status_exited(0), "aslr checks failed")
}

/// tests/user/drm.c: DRM/KMS on the firmware framebuffer (ADR 0033). While
/// the program holds the screen it must show its green framebuffer; once
/// it exits the console has the screen back.
fn drm() -> Result<(), &'static str> {
    use crate::drivers::fbcon::pixel_rgb;
    if crate::drivers::fbcon::size().is_none() {
        return Ok(()); // No framebuffer: nothing to show on.
    }
    let p = spawn(&path("drm"), &[b"drm"], &[]).map_err(|_| "spawn failed")?;
    let mut green = false;
    while !p.is_zombie() {
        green |= pixel_rgb(40, 40) == Some((0, 255, 0));
        crate::time::sleep_ns(5_000_000);
    }
    let status = p.wait();
    super::reap(&p);
    ensure(status == wait_status_exited(0), "drm checks failed")?;
    ensure(green, "the screen never showed the program's framebuffer")?;
    ensure(pixel_rgb(40, 40) != Some((0, 255, 0)), "the console did not take the screen back")
}

/// tests/native/raw/abi.c: the native interface (ADR 0031), called directly.
fn native_abi() -> Result<(), &'static str> {
    ensure(run("native-abi", &[b"native-abi"])? == wait_status_exited(0), "native ABI checks failed")
}

/// tests/native/*.c: C programs on slate-libc (ADR 0031).
fn native_libc() -> Result<(), &'static str> {
    ensure(run("native-hello", &[b"native-hello"])? == wait_status_exited(0), "slate-libc hello failed")?;
    let p = spawn(&path("native-libc"), &[b"native-libc"], &[b"PATH=/bin:/sbin", b"SLATE=1"])
        .map_err(|_| "spawn failed")?;
    let status = p.wait();
    super::reap(&p);
    ensure(status == wait_status_exited(0), "slate-libc checks failed")?;
    ensure(run("native-threads", &[b"native-threads"])? == wait_status_exited(0), "slate-libc thread checks failed")?;
    ensure(run("native-math", &[b"native-math"])? == wait_status_exited(0), "slate-libc floating-point checks failed")?;
    ensure(run("native-posix", &[b"native-posix"])? == wait_status_exited(0), "slate-libc POSIX checks failed")
}

/// Slate mode (ADR 0032): with Linux compatibility mode off, Linux
/// programs (and native programs outside the system tree) are refused and
/// running ones stop; Slate's own programs still run.
fn slate_mode() -> Result<(), &'static str> {
    use super::domain::{self, Domain, LINUX_OFF};
    let sleeper = spawn("/bin/busybox", &[b"sleep", b"30"], &[]).map_err(|_| "spawning BusyBox failed")?;
    ensure(sleeper.domain() == Domain::Linux, "BusyBox is not in the Linux domain")?;
    domain::set_compat(false);
    let checks = (|| {
        let status = sleeper.wait();
        super::reap(&sleeper);
        ensure(status == wait_status_signaled(9), "a Linux program kept running in Slate mode")?;
        ensure(spawn(&path("hello"), &[b"hello"], &[]).err() == Some(LINUX_OFF), "a Linux program was not refused")?;
        ensure(
            spawn(&path("native-hello"), &[b"native-hello"], &[]).err() == Some(LINUX_OFF),
            "a native program outside the system tree was not refused",
        )?;
        let p = spawn("/bin/true", &[b"true"], &[]).map_err(|_| "Slate's own true was refused")?;
        ensure(p.domain() == Domain::Slate, "Slate's own true is not in the Slate domain")?;
        let status = p.wait();
        super::reap(&p);
        ensure(status == wait_status_exited(0), "Slate's own true failed in Slate mode")
    })();
    domain::set_compat(true);
    checks?;
    ensure(run("hello", &[b"hello"])? == wait_status_exited(0), "hello failed with compatibility mode back on")
}

fn resolve() -> Result<(), &'static str> {
    ensure(run("resolve", &[b"resolve"])? == wait_status_exited(0), "openat2 and file handle checks failed")
}

fn rseq() -> Result<(), &'static str> {
    ensure(run("rseq", &[b"rseq"])? == wait_status_exited(0), "rseq checks failed")
}

fn syscalls() -> Result<(), &'static str> {
    ensure(run("syscalls", &[b"syscalls", b"--check"])? == wait_status_exited(0), "user syscall checks failed")
}

fn fork_threads() -> Result<(), &'static str> {
    ensure(run("forkthreads", &[b"forkthreads"])? == wait_status_exited(0), "writes were lost across fork")
}

fn malloc_fork() -> Result<(), &'static str> {
    ensure(run("mallocfork", &[b"/test/mallocfork"])? == wait_status_exited(0), "malloc state broke across fork")
}

fn render_pool() -> Result<(), &'static str> {
    ensure(run("renderpool", &[b"renderpool"])? == wait_status_exited(0), "a render pool's semaphores or malloc broke")
}

fn cow_stale() -> Result<(), &'static str> {
    ensure(
        run("cowstale", &[b"cowstale", b"crash"])? == wait_status_exited(0),
        "a copy-on-write split let a stale copy be read",
    )
}

fn segfault() -> Result<(), &'static str> {
    ensure(run("segfault", &[b"segfault"])? == wait_status_signaled(11), "NULL dereference did not kill with SIGSEGV")
}

fn fpu() -> Result<(), &'static str> {
    // More processes than CPUs, so they preempt each other mid-computation.
    let n = crate::sched::cpu_count() * 3;
    let procs: Vec<_> =
        (0..n).map(|_| spawn(&path("fpu"), &[b"fpu"], &[]).map_err(|_| "spawn failed")).collect::<Result<_, _>>()?;
    for p in procs {
        let status = p.wait();
        super::reap(&p);
        ensure(status == wait_status_exited(0), "FPU state was corrupted across a context switch")?;
    }
    Ok(())
}

fn random() -> Result<(), &'static str> {
    ensure(crate::random::self_test(), "ChaCha20 does not match the RFC 8439 test vector")
}
