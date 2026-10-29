// SPDX-License-Identifier: MIT OR Apache-2.0

//! The packages scenario (M21 phase 6, ADR 0070, ADR 0071): quarry on an
//! installed system's SlateFS root, where every change is a transaction
//! on a snapshot. A package installed works at once and is still there
//! after a restart; `slate-update rollback` brings back the system as it
//! was before the change, `/home` untouched. The base system is packages
//! too: `slate-base` upgrades to a newer release and rolls back, and
//! Strata (`slate-desktop`) is removed and added again from the
//! repository every system carries.

use std::time::Instant;

use crate::qemu::{Console, base_command, strip_ansi};
use crate::{Opts, Result, image, target_dir};

pub fn packages_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    crate::quarry::test_repos()?;
    crate::basepkg::base_next_repo()?;
    let v = crate::basepkg::version();
    let ca = &crate::basepkg::system()?.ca.manifest.version;
    let repos = crate::hostnet::StaticServer::start(target_dir().join("quarry/www"))?;
    let img = image::build(o, "", "slate-packages.img", image::Root::Disk)?;
    let boot = || -> Result<Console> {
        let mut c = base_command(o, &img)?;
        c.args(["-display", "none", "-monitor", "none", "-serial", "stdio"]);
        Console::start(c)
    };
    let fail = |c: &mut Console, e: String| -> String {
        c.kill();
        let _ = std::fs::write(target_dir().join("packages-scenario.log"), strip_ansi(&c.log));
        format!("packages scenario: {e} (log in target/packages-scenario.log)")
    };
    let repo = format!("echo 'main http://10.0.2.2:{}/v1' > /etc/quarry/repos", repos.port);
    // 1: a package installed as a transaction works at once.
    let mut c = boot()?;
    let r = (|| -> Result {
        c.login()?;
        c.run("echo keep > /home/data", "", 10)?;
        c.run(&repo, "", 10)?;
        c.run("quarry update", "main: 3 packages", 30)?;
        c.run(
            "quarry install hello",
            "system-3 has the change and boots next time; system-2 is the system as it was",
            60,
        )?;
        c.run("hello", "hello 1.0", 10)?;
        c.run("slate-update status | tail -1", "default=system-3 fallback=system-2 tries=1 pending=1", 10)?;
        // Nothing to do: no new system.
        c.run("quarry upgrade; slate-update status | grep -c system-", "everything is up to date", 30)?;
        c.send("reboot\r")?;
        c.wait_exit(30).map(|_| ())
    })();
    r.map_err(|e| fail(&mut c, e))?;
    // 2: the new system boots with the package; it is confirmed.
    let mut c = boot()?;
    let r = (|| -> Result {
        c.wait_for("trying system-3", 60)?;
        c.login()?;
        c.run(
            "hello; quarry list | cut -d' ' -f1 | tr '\\n' ,",
            "ca-certificates,hello,libgreet,slate-apps,slate-base,slate-desktop,",
            10,
        )?;
        c.run("sleep 1; slate-update status | tail -1", "default=system-3 fallback=system-2 tries=0 pending=0", 10)?;
        c.run("slate-update rollback", "system-2 boots next time", 10)?;
        c.send("reboot\r")?;
        c.wait_exit(30).map(|_| ())
    })();
    r.map_err(|e| fail(&mut c, e))?;
    // 3: rolled back: the system as it was, the data as it is.
    let mut c = boot()?;
    let r = (|| -> Result {
        c.login()?;
        c.run("command -v hello || echo no-''hello", "no-hello", 10)?;
        c.run("cat /home/data", "keep", 10)?;
        c.run("echo n=$(quarry list | grep -v '^ca-certificates ' | grep -cv '^slate-')", "n=0", 10)?;
        c.poweroff()
    })();
    r.map_err(|e| fail(&mut c, e))?;
    // 4: the base system upgrades to a newer release, live.
    let repos = format!(
        "printf 'install file:///var/lib/quarry/install\\nnext http://10.0.2.2:{}/base-next\\n' > /etc/quarry/repos",
        repos.port
    );
    let mut c = boot()?;
    let r = (|| -> Result {
        c.login()?;
        c.run(&repos, "", 10)?;
        // slate-desktop and slate-apps, and slate-firmware-gpu when the
        // build had AMD's firmware (ADR 0173).
        let media = 2 + usize::from(crate::gpufw::files().is_some());
        c.run("quarry update | sort | tr '\\n' ,", &format!("install: {media} packages,next: 1 packages,"), 30)?;
        c.run(
            "quarry list | cut -d' ' -f1,2 | tr '\\n' ,",
            &format!("ca-certificates {ca},slate-apps {v},slate-base {v},slate-desktop {v},"),
            10,
        )?;
        c.run("quarry remove slate-base", "slate-base is the system itself and cannot be removed", 10)?;
        c.run("quarry upgrade", &format!("upgrading slate-base {v} -> {v}.1"), 120)?;
        c.run("cat /usr/share/slate/release", &format!("Slate {v}.1"), 10)?;
        c.send("reboot\r")?;
        c.wait_exit(30).map(|_| ())
    })();
    r.map_err(|e| fail(&mut c, e))?;
    // 5: the new release boots and is confirmed; roll it back.
    let mut c = boot()?;
    let r = (|| -> Result {
        c.login()?;
        c.run("cat /usr/share/slate/release", &format!("Slate {v}.1"), 10)?;
        c.run("sleep 1; slate-update status | tail -1", "tries=0 pending=0", 10)?;
        c.run("slate-update rollback", "boots next time", 10)?;
        c.send("reboot\r")?;
        c.wait_exit(30).map(|_| ())
    })();
    r.map_err(|e| fail(&mut c, e))?;
    // 6: the release before; Strata removed and added again, offline.
    let mut c = boot()?;
    let r = (|| -> Result {
        c.login()?;
        c.run("echo \"rel=$(cat /usr/share/slate/release)=\"", &format!("rel=Slate {v}="), 10)?;
        c.run("echo base=$(quarry list | grep slate-base | cut -d' ' -f2)=", &format!("base={v}="), 10)?;
        // Through the broker's `desktop` action, as Settings asks (ADR
        // 0102): root needs no approval.
        c.run("slate-approve desktop=remove && echo removed-$((1+1))", "removed-2", 60)?;
        c.run("test -e /bin/strata || echo no-''strata", "no-strata", 10)?;
        c.run("test -e /bin/calculator || echo no-''apps", "no-apps", 10)?;
        c.run("echo n=$(quarry list | grep -c 'slate-desktop\\|slate-apps')=", "n=0=", 10)?;
        c.run("slate-approve desktop=add && echo added-$((1+1))", "added-2", 120)?;
        c.run("test -x /bin/strata && test -x /bin/clock && echo strata-''back", "strata-back", 10)?;
        c.run("quarry list | grep slate-desktop", &format!("slate-desktop {v}"), 10)?;
        c.run("cat /home/data", "keep", 10)?;
        // Full graphics and back (ADR 0173): AMD's firmware, the
        // `slate-firmware-gpu` package, when the build had linux-firmware's
        // files; each change a new system with a rollback.
        if crate::gpufw::files().is_some() {
            c.run("slate-approve graphics=full && echo full-$((1+1))", "full-2", 60)?;
            c.run("test -s /lib/firmware/amdgpu/dcn_3_1_5_dmcub.bin && echo firmware-''there", "firmware-there", 10)?;
            c.run("quarry list | grep slate-firmware-gpu", &format!("slate-firmware-gpu {v}"), 10)?;
            c.run(
                "test -s /usr/share/licenses/slate-firmware-gpu/LICENSE.amdgpu && echo licence-''there",
                "licence-there",
                10,
            )?;
            c.run("slate-approve graphics=slate && echo slate-$((1+1))", "slate-2", 60)?;
            c.run("test -e /lib/firmware/amdgpu/dcn_3_1_5_dmcub.bin || echo firmware-''gone", "firmware-gone", 10)?;
            c.run("slate-approve graphics=sometimes 2>&1 | grep -c 'full or slate'", "1", 10)?;
            // On again: on trial, with the boot menu's way back.
            c.run("slate-approve graphics=full && echo full-$((1+1))", "full-2", 60)?;
            c.run("test -e /var/lib/slate/graphics-trial && echo on-''trial", "on-trial", 10)?;
            c.run("slate-update next | grep -c 'standard graphics'", "1", 10)?;
            c.send("reboot\r")?;
            return c.wait_exit(30).map(|_| ());
        }
        c.poweroff()
    })();
    r.map_err(|e| fail(&mut c, e))?;
    // 7: full graphics' first start (ADR 0173), no AMD card lit here: it
    // goes back to standard graphics by itself, and starts again.
    if crate::gpufw::files().is_some() {
        let mut c = boot()?;
        let r = (|| -> Result {
            c.wait_for("slate-graphics-trial: full graphics didn't start", 120)?;
            c.wait_for("back to standard graphics; restarting", 60)?;
            c.wait_exit(60).map(|_| ())
        })();
        r.map_err(|e| fail(&mut c, e))?;
        let mut c = boot()?;
        let r = (|| -> Result {
            c.login()?;
            c.run("test -e /lib/firmware/amdgpu/dcn_3_1_5_dmcub.bin || echo firmware-''gone", "firmware-gone", 10)?;
            c.run("test -e /var/lib/slate/graphics-trial || echo trial-''over", "trial-over", 10)?;
            c.run("slate-update next | grep -c 'standard graphics'", "0", 10)?;
            c.poweroff()
        })();
        r.map_err(|e| fail(&mut c, e))?;
    }
    crate::slatefsimg::fsck(&img, image::ROOT_OFFSET, "SlateFS root after the packages scenario")?;
    println!(
        "xtask: packages scenario passed (installs as transactions on snapshots, at once and after a restart, \
         rolled back with /home kept; slate-base upgraded and rolled back, slate-desktop removed and added \
         offline through the broker, full graphics on and off, and back by itself on a first start where it didn't light; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
