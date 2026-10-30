// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate's core utilities as one program: it runs the tool named by its
//! argv[0] (through links like /bin/ls -> coreutils), or by its first
//! argument (`coreutils ls -l`). The tools live in this library (unit-tested
//! on the host); the binary only starts it.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod archive;
pub mod attrs;
pub mod awk;
pub mod blkdiscard;
pub mod compress;
pub mod crypt;
pub mod datetime;
pub mod dd;
pub mod diff;
pub mod encode;
pub mod fileops;
pub mod find;
pub mod fstrim;
pub mod grep;
pub mod install;
pub mod join;
pub mod logins;
pub mod ls;
pub mod od;
pub mod printf;
pub mod procs;
pub mod sed;
pub mod simple;
pub mod split;
pub mod strings;
pub mod stty;
pub mod sums;
pub mod sysutil;
pub mod terminfo_caps;
pub mod test;
pub mod text;
pub mod top;
pub mod tput;
pub mod util;

use alloc::vec::Vec;

type Applet = fn(&[Vec<u8>]) -> i32;

/// Every tool, sorted by name.
pub const APPLETS: &[(&str, Applet)] = &[
    ("[", test::bracket),
    ("awk", awk::main),
    ("b2sum", sums::b2sum),
    ("base32", encode::base32),
    ("base64", encode::base64),
    ("basename", simple::basename),
    ("basenc", encode::basenc),
    ("blkdiscard", blkdiscard::blkdiscard),
    ("bunzip2", compress::bunzip2),
    ("bzcat", compress::bzcat),
    ("bzip2", compress::bzip2),
    ("cat", fileops::cat),
    ("chattr", attrs::chattr),
    ("chgrp", fileops::chgrp),
    ("chmod", fileops::chmod),
    ("chown", fileops::chown),
    ("chroot", sysutil::chroot),
    ("cksum", sums::cksum),
    ("clear", simple::clear),
    ("cmp", sysutil::cmp),
    ("comm", text::comm),
    ("cp", fileops::cp),
    ("cut", text::cut),
    ("date", sysutil::date),
    ("dd", dd::main),
    ("df", sysutil::df),
    ("diff", diff::main),
    ("dirname", simple::dirname),
    ("dmesg", sysutil::dmesg),
    ("du", sysutil::du),
    ("echo", simple::echo),
    ("egrep", grep::egrep),
    ("env", simple::env),
    ("expand", text::expand),
    ("expr", sysutil::expr),
    ("false", simple::r#false),
    ("fgrep", grep::fgrep),
    ("find", find::main),
    ("fold", text::fold),
    ("free", sysutil::free),
    ("fstrim", fstrim::fstrim),
    ("grep", grep::main),
    ("groups", simple::groups),
    ("gunzip", compress::gunzip),
    ("gzip", compress::gzip),
    ("head", text::head),
    ("hostname", simple::hostname),
    ("id", simple::id),
    ("install", install::main),
    ("join", join::main),
    ("kill", sysutil::kill),
    ("last", logins::last),
    ("lastlog", logins::lastlog),
    ("ln", fileops::ln),
    ("logname", simple::logname),
    ("ls", ls::main),
    ("lsattr", attrs::lsattr),
    ("lzcat", compress::lzcat),
    ("lzma", compress::lzma),
    ("md5sum", sums::md5sum),
    ("mkdir", fileops::mkdir),
    ("mktemp", fileops::mktemp),
    ("mount", sysutil::mount),
    ("mv", fileops::mv),
    ("nl", text::nl),
    ("nohup", sysutil::nohup),
    ("nproc", simple::nproc),
    ("od", od::main),
    ("paste", text::paste),
    ("printenv", simple::printenv),
    ("printf", printf::main),
    ("ps", procs::ps),
    ("pwd", simple::pwd),
    ("readlink", fileops::readlink),
    ("realpath", fileops::realpath),
    ("rev", text::rev),
    ("rm", fileops::rm),
    ("rmdir", fileops::rmdir),
    ("sed", sed::main),
    ("seq", simple::seq),
    ("setsid", sysutil::setsid),
    ("sha1sum", sums::sha1sum),
    ("sha224sum", sums::sha224sum),
    ("sha256sum", sums::sha256sum),
    ("sha384sum", sums::sha384sum),
    ("sha512sum", sums::sha512sum),
    ("slate-compat", sysutil::slate_compat),
    ("sleep", simple::sleep),
    ("sort", text::sort),
    ("split", split::main),
    ("stat", sysutil::stat),
    ("strings", strings::main),
    ("stty", stty::main),
    ("sum", sums::sum),
    ("sync", simple::sync),
    ("tac", text::tac),
    ("tail", text::tail),
    ("tar", archive::tar),
    ("tee", simple::tee),
    ("test", test::test),
    ("timeout", sysutil::timeout),
    ("top", top::top),
    ("touch", fileops::touch),
    ("tput", tput::main),
    ("tr", text::tr),
    ("true", simple::r#true),
    ("truncate", fileops::truncate),
    ("tty", simple::tty),
    ("umount", sysutil::umount),
    ("uname", simple::uname),
    ("uniq", text::uniq),
    ("unlzma", compress::unlzma),
    ("unxz", compress::unxz),
    ("unzstd", compress::unzstd),
    ("uptime", sysutil::uptime),
    ("users", logins::users),
    ("w", logins::w),
    ("wall", logins::wall),
    ("wc", text::wc),
    ("which", sysutil::which),
    ("who", logins::who),
    ("whoami", simple::whoami),
    ("xargs", sysutil::xargs),
    ("xz", compress::xz),
    ("xzcat", compress::xzcat),
    ("yes", simple::yes),
    ("zcat", compress::zcat),
    ("zstd", compress::zstd),
    ("zstdcat", compress::zstdcat),
];

pub fn ls_mode(m: u32) -> [u8; 10] {
    ls::mode_string(m)
}

fn find(name: &[u8]) -> Option<Applet> {
    APPLETS.iter().find(|(n, _)| n.as_bytes() == name).map(|(_, f)| *f)
}

/// Run the tool `argv[0]` names (or `argv[1]`).
pub fn main() -> i32 {
    let args = slate_rt::env::args();
    let name = args.first().map(|a| slate_rt::fs::basename(a)).unwrap_or(b"coreutils");
    if let Some(f) = find(name) {
        return f(args);
    }
    match args.get(1) {
        Some(n) if n == b"--list" => {
            for (n, _) in APPLETS {
                slate_rt::println!("{n}");
            }
            0
        }
        Some(n) => match find(n) {
            Some(f) => f(&args[1..]),
            None => {
                slate_rt::eprintln!("coreutils: unknown tool '{}'", slate_rt::lossy(n));
                127
            }
        },
        None => {
            slate_rt::eprintln!("usage: coreutils TOOL [ARGS...]   (coreutils --list for the tools)");
            1
        }
    }
}
