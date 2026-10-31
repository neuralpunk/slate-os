// SPDX-License-Identifier: MIT OR Apache-2.0

//! Acceptance runs (ADR 0024): the milestone criteria that need the
//! internet and third-party software, so they stay out of `cargo xtask
//! test`. M12: in an Alpine root on a fresh ext4 disk, Slate runs sshd;
//! the host logs in, clones a repository, builds and runs a C and a Rust
//! project and a Python script. M15: podman runs alpine rootful and
//! rootless (with pasta networking), and docker runs debian. M18a: Sway
//! runs with software rendering and opens foot (`desktop::accept`). M18d:
//! Firefox from a Linux runtime in a Strata window (`linuxapp::accept`).
//! M28: a Flathub app installed, updated and rolled back, in a Strata
//! window, and an AppImage (`flatpak::accept`). M31: Firefox in one
//! click with its progress, on a system without a Linux runtime
//! (`flatpak::browser_fresh`); GNOME's Calculator following Strata's
//! light or dark theme as it changes, with its icon and Strata's fonts
//! (`flatpak::themed`). M33: source packages (autotools, CMake, Meson,
//! Cargo, setuptools) built, tested, installed and run in an Arch Linux
//! box (`boxes::accept`). M30 phase 1: alsa-lib's tools, PipeWire and
//! the PulseAudio server play sound (`sound::pipewire`).
//! M20: Slate's own tools on the real network: names with IPv4 and IPv6
//! addresses, a download over IPv4 from the internet and over IPv6 (from
//! the host's server through QEMU's network, and from the internet when
//! the host has IPv6), the clock from pool.ntp.org. M21: Slate's own TLS
//! client (ADR 0072) against real servers: fetch over HTTPS from sites
//! with RSA and ECDSA chains from different authorities, from a TLS
//! 1.2-only server (ADR 0135), and refusing badssl.com's expired, wrongly
//! named, self-signed and untrusted certificates (it speaks TLS 1.2).

use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::{Opts, Result, image, run_cmd, target_dir};

/// Size of the workbench disk (sparse).
const WORKBENCH_SIZE: &str = "12G";

/// Alpine packages the M12 and M15 checks need.
const PACKAGES: &str =
    "openssh git make gcc musl-dev clang python3 rust cargo podman crun conmon netavark passt shadow-subids docker";

/// A small public repository for the HTTPS clone (README: "Hello World!").
const PUBLIC_REPO: &str = "https://github.com/octocat/Hello-World";

/// The guest's setup, run inside the workbench (Alpine's /bin/sh).
fn setup_script() -> String {
    format!(
        "#!/bin/sh\n\
         set -e\n\
         apk update -q\n\
         apk add -q {PACKAGES}\n\
         ssh-keygen -A\n\
         chown -R root:root /root\n\
         chmod 700 /root/.ssh\n\
         chmod 600 /root/.ssh/authorized_keys\n\
         /usr/sbin/sshd -E /var/log/sshd.log\n\
         adduser -D slate\n\
         echo slate:100000:65536 > /etc/subuid\n\
         echo slate:100000:65536 > /etc/subgid\n\
         chmod u+s /usr/bin/newuidmap /usr/bin/newgidmap\n\
         chmod 1777 /var/tmp\n\
         dockerd --iptables=false --ip6tables=false --bridge=none > /var/log/dockerd.log 2>&1 &\n\
         echo setup-ok\n"
    )
}

/// One check over ssh: a name, the remote command, text its output must
/// contain, the exit status it must have, and how long it may take.
#[derive(Clone)]
struct Check {
    name: &'static str,
    command: String,
    want: &'static [&'static str],
    status: i32,
    tty: bool,
    secs: u64,
}

fn checks(repo_url: &str) -> Vec<Check> {
    let c = |name, command: &str, want, secs| Check {
        name,
        command: command.to_string(),
        want,
        status: 0,
        tty: false,
        secs,
    };
    vec![
        c("ssh_login", "uname -sm; id -u", &["Linux x86_64", "\n0"], 30),
        Check { status: 7, ..c("exit_status", "exit 7", &[], 30) },
        Check { tty: true, ..c("pty_session", "tty; test -t 0 && echo pty-ok", &["/dev/pts/", "pty-ok"], 30) },
        c(
            "git_clone",
            &format!("cd /root && rm -rf demo && git clone -q {repo_url} demo && git -C demo log --format=%s"),
            &["M12 acceptance demo"],
            120,
        ),
        c(
            "git_commit",
            "cd /root/demo && git -c user.name=slate -c user.email=slate@localhost commit -q --allow-empty -m second \
             && git log --oneline | wc -l",
            &["2"],
            60,
        ),
        c(
            "git_clone_https",
            &format!("cd /root && rm -rf hw && git clone -q --depth 1 {PUBLIC_REPO} hw && cat hw/README"),
            &["Hello World!"],
            120,
        ),
        c("c_gcc_make", "cd /root/demo/c && make -s CC=gcc && ./c-demo", &["c-demo:", " ok"], 300),
        c("c_clang", "cd /root/demo/c && make -s clean && make -s CC=clang && ./c-demo", &["c-demo:", " ok"], 300),
        c(
            "rust_cargo_build",
            "cd /root/demo/rust && cargo build --release -q && ./target/release/rust-demo",
            &["rust-demo:", " ok"],
            900,
        ),
        c("rust_cargo_test", "cd /root/demo/rust && cargo test -q 2>&1", &["test result: ok. 2 passed"], 900),
        c("python", "python3 /root/demo/check.py", &["python-demo:", " ok"], 120),
        // M15. newuidmap/newgidmap are made set-user-ID in the setup:
        // Alpine gives them file capabilities, which Slate doesn't apply
        // yet (docs/GAPS.md).
        c(
            "m15_podman_rootful",
            "podman run --rm --network=none alpine sh -c 'echo rootful-ok; cat /proc/self/uid_map'",
            &["rootful-ok", "4294967295"],
            600,
        ),
        c(
            "m15_podman_rootless",
            &format!(
                "su slate -c \"cd; podman run --rm alpine sh -c 'echo uid=\\$(id -u); head -1 /proc/self/uid_map; \
                 wget -qO- {repo_url}/HEAD'\""
            ),
            &["uid=0", " 1000 ", "ref: refs/heads/"],
            600,
        ),
        Check {
            status: 3,
            ..c("m15_docker", "docker run --rm debian sh -c 'grep ^NAME /etc/os-release; exit 3'", &["Debian"], 600)
        },
    ]
}

pub fn run(o: &Opts) -> Result {
    let started = Instant::now();
    let dir = target_dir().join("accept");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let key = dir.join("id_ed25519");
    run_cmd(Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-C", "slate-accept", "-f"]).arg(&key))?;
    let workbench = make_workbench(&dir, &key)?;
    let repo = make_demo_repo(&dir)?;
    let web = crate::hostnet::StaticServer::start(dir.join("www"))?;
    let repo_url = format!("http://10.0.2.2:{}/{}", web.port, repo);
    let port = free_port()?;

    // The acceptance runs Linux software (Alpine, compilers, Podman), so
    // Linux compatibility mode is on (ADR 0032).
    // `--cmdline` adds kernel arguments (`slate.strace=pasta` to look at
    // one program); `SLATE_ACCEPT_ONLY=name,...` runs only those checks.
    let cmdline = format!("slate.compat=on {}", o.cmdline.as_deref().unwrap_or(""));
    let only: Option<Vec<String>> =
        std::env::var("SLATE_ACCEPT_ONLY").ok().map(|v| v.split(',').map(str::to_string).collect());
    let img = image::build(o, cmdline.trim_end(), "slate-accept.img", image::Root::Disk)?;
    let mut qemu = crate::qemu::base_command_net(o, &img, &format!(",hostfwd=tcp:127.0.0.1:{port}-:22"))?;
    crate::qemu::add_disk(&mut qemu, 0, &workbench);
    qemu.args(["-display", "none", "-monitor", "none", "-serial", "stdio"]);
    let mut console = crate::qemu::Console::start(qemu)?;
    let result = (|| -> Result {
        console.login()?;
        println!("xtask: accept: installing packages in the workbench ({PACKAGES})");
        // Port 22 is for the workbench's OpenSSH (M12's acceptance), not
        // Slate's own sshd (ADR 0030), which the install scenario tests.
        console.run("service sshd stop; echo stopped$((1+1))", "stopped2", 30)?;
        console.run(
            "mkdir -p /w && mount -t ext4 /dev/vdb /w && mount -t proc proc /w/proc && mount -t devtmpfs dev /w/dev \
             && mount -t devpts devpts /w/dev/pts && mount -t tmpfs tmpfs /w/tmp && mount -t tmpfs run /w/run \
             && mount -t sysfs sys /w/sys && mount -t cgroup2 cg /w/sys/fs/cgroup && cp /etc/resolv.conf /w/etc/ \
             && chroot /w /bin/sh /setup.sh",
            "setup-ok",
            1500,
        )?;
        // M13: quarry resolves a name through Slate's own DNS client and
        // fetches over HTTP (example.com has no repository: a 404 proves
        // both worked).
        console.run(
            "mkdir -p /tmp/qr/usr/share/quarry/keys /tmp/qr/etc/quarry && cp /usr/share/quarry/keys/dev.pub /tmp/qr/usr/share/quarry/keys/ \
             && echo 'net http://example.com/quarry-accept' > /tmp/qr/etc/quarry/repos && quarry --root /tmp/qr update",
            "HTTP 404",
            60,
        )?;
        println!("ACCEPT: PASS m13::quarry_dns_http");
        if only.is_none() {
            m20(&mut console, web.port, &repo)?;
            m21(&mut console)?;
        }
        let ssh = Ssh { key: key.clone(), port };
        ssh.wait_ready()?;
        let mut failed = Vec::new();
        // SLATE_ACCEPT_REPEAT=N runs each check N times (to catch a flaky one).
        let repeat: usize = std::env::var("SLATE_ACCEPT_REPEAT").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
        let chosen =
            checks(&repo_url).into_iter().filter(|c| only.as_ref().is_none_or(|o| o.iter().any(|n| n == c.name)));
        for c in chosen.flat_map(|c| std::iter::repeat_n(c, repeat)) {
            let t = Instant::now();
            let (status, out) = ssh.run(&c.command, c.tty, c.secs)?;
            std::fs::write(dir.join(format!("{}.log", c.name)), &out).map_err(|e| e.to_string())?;
            let missing: Vec<&str> = c.want.iter().copied().filter(|w| !out.contains(w)).collect();
            let ok = status == Some(c.status) && missing.is_empty();
            let label = c.name.strip_prefix("m15_").map_or_else(|| format!("m12::{}", c.name), |n| format!("m15::{n}"));
            println!("ACCEPT: {} {label} ({:.1}s)", if ok { "PASS" } else { "FAIL" }, t.elapsed().as_secs_f64());
            if !ok {
                println!("  exit {status:?} (want {}), missing {missing:?}; output:\n{}", c.status, tail(&out, 2000));
                failed.push(c.name);
            }
        }
        console.poweroff()?;
        if !failed.is_empty() {
            return Err(format!("acceptance checks failed: {}", failed.join(", ")));
        }
        Ok(())
    })();
    web.stop();
    std::fs::write(dir.join("console.log"), crate::qemu::strip_ansi(&console.log)).map_err(|e| e.to_string())?;
    if let Err(e) = result {
        console.kill();
        return Err(format!("{e} (logs in {})", dir.display()));
    }
    fsck(&workbench)?;
    if only.is_some() {
        println!("xtask: accept: the chosen checks passed ({:.0}s)", started.elapsed().as_secs_f64());
        return Ok(());
    }
    // M18a: Sway and foot (ADR 0033).
    crate::desktop::accept()?;
    // M18d: a Linux program in Strata (ADR 0038).
    crate::linuxapp::accept()?;
    // M28: Flatpak and AppImage (ADR 0114).
    crate::flatpak::accept()?;
    // M31: Firefox in one click on a fresh system (ADR 0181).
    crate::flatpak::browser_fresh()?;
    // M31: a GTK app follows Strata's theme, with its icon (ADR 0182).
    crate::flatpak::themed()?;
    // M33: Linux from source in an Arch box (ADR 0183).
    crate::boxes::accept()?;
    // M30 phase 1: PipeWire plays sound (ADR 0184).
    crate::sound::pipewire(false, true)?;
    println!(
        "xtask: accept: M12 passed (ssh, git over HTTP and HTTPS, C with GCC and Clang, Rust, Python; \
         workbench passes e2fsck), M13's DNS check, M15 (podman rootful and rootless, docker), M18a (Sway \
         with foot on virtio-gpu, typing, D-Bus), M18d (Firefox in Strata), M28's Flatpak and AppImage, M31's Firefox in one click and themed GTK app, M33's source packages in an Arch box, M20 (lookups, fetch over IPv4 \
         and IPv6, NTP) and M21 (HTTPS from three sites with Slate's TLS client) ({:.0}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Whether the host reaches the internet over IPv6 (QEMU's user network
/// relays the guest's IPv6 through the host's).
fn host_has_ipv6() -> bool {
    use std::net::ToSocketAddrs;
    let Ok(addrs) = "example.com:80".to_socket_addrs() else { return false };
    addrs.filter(|a| a.is_ipv6()).any(|a| std::net::TcpStream::connect_timeout(&a, Duration::from_secs(5)).is_ok())
}

/// M20 (ADR 0052): Slate's own lookup and fetch, and netd's NTP, on the
/// real network. `web` is the host's server (reachable as fec0::2 over
/// IPv6), with the demo repository at `repo`.
fn m20(console: &mut crate::qemu::Console, web: u16, repo: &str) -> Result {
    let pass = |name: &str| println!("ACCEPT: PASS m20::{name}");
    console.run("lookup -4 example.com", "example.com has address", 30)?;
    console.run("lookup -6 example.com", "example.com has IPv6 address", 30)?;
    pass("lookup");
    console.run(
        "fetch -q -o /tmp/example http://example.com/ && grep -q 'Example Domain' /tmp/example && echo got$((1+1))",
        "got2",
        60,
    )?;
    pass("fetch_ipv4_internet");
    console.run(&format!("fetch -6 -q http://[fec0::2]:{web}/{repo}/HEAD"), "ref: refs/heads/", 60)?;
    pass("fetch_ipv6");
    if host_has_ipv6() {
        console.run(
            "fetch -6 -q -o /tmp/example6 http://example.com/ && grep -q 'Example Domain' /tmp/example6 \
             && echo got6-$((1+1))",
            "got6-2",
            60,
        )?;
        pass("fetch_ipv6_internet");
    } else {
        println!("ACCEPT: SKIP m20::fetch_ipv6_internet (the host has no IPv6 route to the internet)");
    }
    // netd's SNTP client with the image's own setting (pool.ntp.org).
    console.run(
        "for i in $(seq 120); do grep -q '^ntp synced pool.ntp.org' /run/netd/status && break; sleep 0.5; done; \
         grep '^ntp' /run/netd/status | sed 's/^ntp synced pool/ntp-synced-pool/'",
        "ntp-synced-pool",
        90,
    )?;
    pass("ntp");
    Ok(())
}

/// M21 (ADR 0072): Slate's TLS 1.3 client on the internet, through fetch.
/// The `$((1+1))` keeps the wanted text out of the echoed command line.
fn m21(console: &mut crate::qemu::Console) -> Result {
    let pass = |name: &str| println!("ACCEPT: PASS m21::{name}");
    // DigiCert-style RSA (example.com), Google Trust Services with ECDSA
    // P-256 (www.google.com), and Let's Encrypt's ISRG chain.
    for (name, url, text) in [
        ("https_example", "https://example.com/", "Example Domain"),
        ("https_google", "https://www.google.com/", "<html"),
        ("https_letsencrypt", "https://letsencrypt.org/", "Let's Encrypt"),
        ("https_tls12", "https://tls-v1-2.badssl.com:1012/", "tls-v1-2.badssl.com"),
    ] {
        console.run(
            &format!("fetch -q -o /tmp/{name} {url} && grep -q \"{text}\" /tmp/{name} && echo {name}-$((1+1))"),
            &format!("{name}-2"),
            60,
        )?;
        pass(name);
    }
    // What must be refused, by what fetch says.
    for (name, host, why) in [
        ("refuse_expired", "expired", "not valid now"),
        ("refuse_wrong_host", "wrong.host", "for another name"),
        ("refuse_self_signed", "self-signed", "not from a trusted authority"),
        ("refuse_untrusted_root", "untrusted-root", "not from a trusted authority"),
    ] {
        console.run(
            &format!(
                "fetch -q -o /tmp/{name} https://{host}.badssl.com/ 2>&1 | grep -q \"{why}\" && echo {name}-$((1+1))"
            ),
            &format!("{name}-2"),
            60,
        )?;
        pass(name);
    }
    Ok(())
}

fn tail(s: &str, n: usize) -> &str {
    let mut start = s.len().saturating_sub(n);
    while !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

fn free_port() -> Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    Ok(l.local_addr().map_err(|e| e.to_string())?.port())
}

/// The workbench disk: the Alpine minirootfs, the setup script and the
/// run's public key, as ext4 owned by root (`unshare -r` maps the host user
/// to root while mkfs reads the files).
fn make_workbench(dir: &Path, key: &Path) -> Result<PathBuf> {
    let stage = dir.join("workbench-root");
    run_cmd(Command::new("cp").arg("-a").arg(crate::alpine::fetch()?).arg(&stage))?;
    std::fs::write(stage.join("setup.sh"), setup_script()).map_err(|e| e.to_string())?;
    let ssh_dir = stage.join("root/.ssh");
    std::fs::create_dir_all(&ssh_dir).map_err(|e| e.to_string())?;
    let mut pubkey = key.as_os_str().to_owned();
    pubkey.push(".pub");
    std::fs::copy(&pubkey, ssh_dir.join("authorized_keys")).map_err(|e| e.to_string())?;
    let img = dir.join("workbench.img");
    run_cmd(
        Command::new("unshare")
            .args(["-r", "mkfs.ext4", "-q", "-F", "-b", "4096", "-L", "workbench", "-d"])
            .arg(&stage)
            .arg(&img)
            .arg(WORKBENCH_SIZE),
    )
    .map_err(|e| format!("{e} (needs util-linux unshare and e2fsprogs)"))?;
    Ok(img)
}

/// Commit tests/accept/projects into a bare repository served over HTTP; returns
/// its path under the web root. Git runs with the user's configuration
/// ignored (no signing, no hooks).
fn make_demo_repo(dir: &Path) -> Result<String> {
    let src = dir.join("demo-src");
    run_cmd(Command::new("cp").arg("-a").arg(crate::root().join("tests/accept/projects")).arg(&src))?;
    let git = |args: &[&str], cwd: &Path| -> Result {
        run_cmd(
            Command::new("git")
                .args(["-c", "user.name=Slate", "-c", "user.email=slate@localhost", "-c", "commit.gpgsign=false"])
                .args(args)
                .current_dir(cwd)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .stdout(Stdio::null()),
        )
    };
    git(&["init", "-q", "-b", "main"], &src)?;
    git(&["add", "."], &src)?;
    git(&["commit", "-q", "-m", "M12 acceptance demo"], &src)?;
    let www = dir.join("www");
    std::fs::create_dir_all(&www).map_err(|e| e.to_string())?;
    git(&["clone", "-q", "--bare", src.to_str().unwrap(), "demo.git"], &www)?;
    let bare = www.join("demo.git");
    git(&["repack", "-q", "-a", "-d"], &bare)?;
    git(&["update-server-info"], &bare)?;
    Ok("demo.git".into())
}

fn fsck(img: &Path) -> Result {
    let out = Command::new("e2fsck").args(["-f", "-n"]).arg(img).output().map_err(|e| e.to_string())?;
    if out.status.success() {
        return Ok(());
    }
    Err(format!(
        "workbench: e2fsck found problems:\n{}{}",
        tail(&String::from_utf8_lossy(&out.stdout), 4000),
        String::from_utf8_lossy(&out.stderr)
    ))
}

/// ssh to the guest with the run's key only: the user's configuration and
/// agent are ignored, host keys are not recorded.
struct Ssh {
    key: PathBuf,
    port: u16,
}

impl Ssh {
    fn command(&self, tty: bool) -> Command {
        let mut c = Command::new("ssh");
        c.args(["-F", "/dev/null", "-i"]).arg(&self.key);
        for o in [
            "IdentitiesOnly=yes",
            "IdentityAgent=none",
            "BatchMode=yes",
            "StrictHostKeyChecking=no",
            "UserKnownHostsFile=/dev/null",
            "LogLevel=ERROR",
            "ConnectTimeout=20",
        ] {
            c.args(["-o", o]);
        }
        if tty {
            c.arg("-tt");
        }
        c.args(["-p", &self.port.to_string(), "root@127.0.0.1"]);
        c
    }

    /// Run `cmd`; returns its exit status (None on timeout) and output.
    fn run(&self, cmd: &str, tty: bool, secs: u64) -> Result<(Option<i32>, String)> {
        let mut c = self.command(tty);
        c.arg(cmd).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = c.spawn().map_err(|e| format!("ssh: {e}"))?;
        let (mut out, mut err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
        let t_out = std::thread::spawn(move || {
            let mut s = Vec::new();
            let _ = out.read_to_end(&mut s);
            s
        });
        let t_err = std::thread::spawn(move || {
            let mut s = Vec::new();
            let _ = err.read_to_end(&mut s);
            s
        });
        let deadline = Instant::now() + Duration::from_secs(secs);
        let status = loop {
            if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
                break s.code();
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let mut text = String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned();
        text.push_str(&String::from_utf8_lossy(&t_err.join().unwrap_or_default()));
        Ok((status, text.replace('\r', "")))
    }

    fn wait_ready(&self) -> Result {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let (Some(0), _) = self.run("true", false, 20)? {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err("sshd in the guest does not accept the key".into());
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}
