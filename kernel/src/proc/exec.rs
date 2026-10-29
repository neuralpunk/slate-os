// SPDX-License-Identifier: MIT OR Apache-2.0

//! Loading a program into a fresh address space and building its initial
//! stack (System V AMD64 psABI §3.4.1, "Initial Stack and Register State";
//! auxiliary vector tags from getauxval(3), values from musl `elf.h`,
//! ADR 0009). Scripts starting with `#!` run their interpreter
//! (execve(2), "Interpreter scripts").

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use slate_elf::{ET_DYN, Elf, PF_W, PF_X, PT_LOAD};

use super::aslr::Layout;
use crate::abi::linux::errno::*;
use crate::fs::vfs::{self, Dentry, FileType};
use crate::mm::PAGE_SIZE;
use crate::mm::aspace::{AddressSpace, Prot};

// Auxiliary vector tags.
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_FLAGS: u64 = 8;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_PLATFORM: u64 = 15;
const AT_HWCAP: u64 = 16;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
/// rseq(2)'s feature size and the area's alignment (librseq's rseq.2
/// names them; their types observed in Linux's auxiliary vector).
const AT_RSEQ_FEATURE_SIZE: u64 = 27;
const AT_RSEQ_ALIGN: u64 = 28;
const AT_EXECFN: u64 = 31;
const AT_SYSINFO_EHDR: u64 = 33;

/// Total size limit for argument and environment strings (ARG_MAX).
const ARG_MAX: usize = 128 * 1024;
/// Nested `#!` interpreters allowed before ELOOP.
const MAX_INTERPRETERS: usize = 4;
/// Copy chunk size when reading segments from a file.
const CHUNK: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct Image {
    pub entry: u64,
    pub stack_pointer: u64,
    /// Where a position-independent program was put (0 for one linked at
    /// a fixed address).
    pub bias: u64,
}

/// A loaded program: its image plus the (possibly rewritten) argv and the
/// path that was finally executed.
#[derive(Debug)]
pub struct Loaded {
    pub aspace: AddressSpace,
    pub image: Image,
    pub argv: Vec<Vec<u8>>,
    pub path: alloc::string::String,
    /// The program file that was loaded (the interpreter, for a script).
    pub exe: Arc<Dentry>,
    /// The credentials after the exec (set-ID bits applied).
    pub cred: super::cred::Cred,
    /// The system-call interface the program asked for (ADR 0031).
    pub abi: super::Abi,
    /// The domain it runs in (ADR 0032).
    pub domain: super::domain::Domain,
    /// The system grant (ADR 0090): a program signed UPDATER, run as root
    /// in the Slate domain.
    pub grant: bool,
    /// personality(2) after the exec (ADR 0092).
    pub persona: u32,
    /// The JIT permission (ADR 0093).
    pub jit: bool,
    /// Per-app permissions (ADR 0130) and the key-slot permission.
    pub app: u32,
    pub keyslots: bool,
}

fn page_floor(a: u64) -> u64 {
    a & !(PAGE_SIZE - 1)
}

fn page_ceil(a: u64) -> u64 {
    a.div_ceil(PAGE_SIZE) * PAGE_SIZE
}

fn read_exact(d: &Dentry, offset: u64, buf: &mut [u8]) -> Result<(), Errno> {
    let mut done = 0;
    while done < buf.len() {
        let n = d.inode.read_at(offset + done as u64, &mut buf[done..])?;
        if n == 0 {
            return Err(ENOEXEC);
        }
        done += n;
    }
    Ok(())
}

/// Resolve and load `path` (relative to `cwd`, absolute paths from
/// `root`) into a new address space.
pub fn load_path(
    root: &Arc<Dentry>,
    cwd: &Arc<Dentry>,
    path: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
    cred: &super::cred::Cred,
) -> Result<Loaded, Errno> {
    let mut argv: Vec<Vec<u8>> = argv.iter().map(|a| a.to_vec()).collect();
    let mut path = path.to_vec();
    for _ in 0..=MAX_INTERPRETERS {
        let p = core::str::from_utf8(&path).map_err(|_| ENOENT)?;
        let d = executable(root, cwd, p, cred)?;
        let size = d.metadata().size;
        let mut head = vec![0u8; (size as usize).min(256)];
        read_exact(&d, 0, &mut head)?;
        if head.starts_with(b"#!") {
            // `#!interpreter [one optional argument]` on the first line.
            let line = head[2..].split(|&b| b == b'\n').next().unwrap_or(&[]);
            let line: Vec<u8> = line.iter().copied().skip_while(|b| *b == b' ' || *b == b'\t').collect();
            let mut parts = line.splitn(2, |b| *b == b' ' || *b == b'\t');
            let interp = parts.next().filter(|i| !i.is_empty()).ok_or(ENOEXEC)?.to_vec();
            let arg = parts.next().map(|a| a.trim_ascii().to_vec()).filter(|a| !a.is_empty());
            let mut new_argv = vec![interp.clone()];
            new_argv.extend(arg);
            new_argv.push(path.clone());
            new_argv.extend(argv.iter().skip(1).cloned());
            argv = new_argv;
            path = interp;
            continue;
        }
        let argv_refs: Vec<&[u8]> = argv.iter().map(|a| a.as_slice()).collect();
        let mut aspace = AddressSpace::new().map_err(|_| ENOMEM)?;
        // The domain: Slate for native programs from the system tree, Linux
        // otherwise; the Linux domain needs compatibility mode (ADR 0032).
        // Decided before loading, so a refused exec costs nothing.
        // The Linux domain is sticky: a Linux process running one of
        // Slate's programs keeps it in the Linux domain, or it could use
        // Slate's tools to do what the domain forbids.
        // The Slate domain needs a signature by a key the kernel trusts,
        // and the system tree unless the program is signed ANYWHERE (ADR
        // 0090).
        let from_linux = super::domain::linux_caller();
        let signed = if !from_linux && abi_of_file(&d)? == super::Abi::Native {
            let flags = super::sign::flags_of(&d, |off, buf| read_exact(&d, off, buf))?;
            if flags.is_none() {
                super::domain::log_unsigned(p);
            }
            flags.filter(|f| f & slate_elfsign::ANYWHERE != 0 || vfs::in_system_tree(&d))
        } else {
            None
        };
        // An unsigned native program that quarry installed and listed runs
        // in the Slate domain, confined to what it declared (ADR 0130).
        let listed = if signed.is_none() && !from_linux && abi_of_file(&d)? == super::Abi::Native {
            super::apps::declared(&d)
        } else {
            None
        };
        let app = super::apps::after_exec(super::apps::current(), listed.filter(|_| signed.is_none()));
        let domain = if signed.is_some() || listed.is_some() {
            super::domain::Domain::Slate
        } else {
            super::domain::Domain::Linux
        };
        if domain == super::domain::Domain::Linux && !super::domain::compat() {
            super::domain::log_refusal(p);
            return Err(super::domain::LINUX_OFF);
        }
        // Set-ID bits of scripts are ignored; those of the program run (the
        // interpreter, for a script) apply, in the Linux domain only: Slate
        // programs get authority from the privilege broker (ADR 0032).
        // They are ignored on a nosuid mount too (execve(2)).
        let mut meta = d.metadata();
        if domain == super::domain::Domain::Slate || vfs::mount_flags(&d) & vfs::MNT_NOSUID != 0 {
            meta.mode &= !(super::cred::S_ISUID | super::cred::S_ISGID);
        }
        // File capabilities, where set-ID bits would count (mount(2)
        // MS_NOSUID: ignored with them).
        let fcaps = (domain == super::domain::Domain::Linux && vfs::mount_flags(&d) & vfs::MNT_NOSUID == 0)
            .then(|| d.inode.get_xattr(super::fcaps::NAME).ok())
            .flatten()
            .and_then(|v| super::fcaps::parse(&v));
        let (new_cred, secure) = cred.after_exec(&meta, fcaps.as_ref());
        // Strict W^X in the Slate domain: no segment writable and executable.
        if domain == super::domain::Domain::Slate {
            let (headers, size) = read_headers(&d)?;
            let elf = Elf::parse_prefix(&headers, size).map_err(|_| ENOEXEC)?;
            if elf.program_headers().any(|ph| ph.kind == PT_LOAD && ph.flags & PF_W != 0 && ph.flags & PF_X != 0) {
                return Err(ENOEXEC);
            }
        }
        // A set-user-ID program is laid out at random whatever its caller
        // asked (personality(2): ADDR_NO_RANDOMIZE is among the flags
        // cleared then).
        let mut persona = super::current().map_or(0, |p| p.persona.load(core::sync::atomic::Ordering::Relaxed));
        if secure {
            persona &= !super::aslr::ADDR_NO_RANDOMIZE;
        }
        let layout = Layout::for_persona(persona);
        let ids = aux_ids(&new_cred, secure);
        let (image, abi) = load_program(&mut aspace, root, cwd, &d, &argv_refs, envp, &path, cred, ids, layout)?;
        // A confined program never gets the system grant or the key slots.
        let confined = app & super::apps::CONFINED != 0;
        let grant = signed.is_some_and(|f| f & slate_elfsign::UPDATER != 0) && new_cred.euid == 0 && !confined;
        let keyslots = signed.is_some_and(|f| f & slate_elfsign::KEYSLOTS != 0) && new_cred.euid == 0 && !confined;
        let jit =
            if confined { app & super::apps::JIT != 0 } else { signed.is_some_and(|f| f & slate_elfsign::JIT != 0) };
        return Ok(Loaded {
            aspace,
            image,
            argv,
            path: alloc::string::String::from(p),
            exe: d,
            cred: new_cred,
            abi,
            domain,
            grant,
            persona,
            jit,
            app,
            keyslots,
        });
    }
    Err(ELOOP)
}

/// Resolve `path` to a regular file the caller may execute.
fn executable(
    root: &Arc<Dentry>,
    cwd: &Arc<Dentry>,
    path: &str,
    cred: &super::cred::Cred,
) -> Result<Arc<Dentry>, Errno> {
    let d = vfs::resolve_in(root, cwd, path, true)?;
    let meta = d.metadata();
    if meta.file_type() != FileType::Regular {
        return Err(if meta.file_type() == FileType::Directory { EISDIR } else { EACCES });
    }
    // Nothing on a noexec mount runs, a script's interpreter included
    // (execve(2): EACCES).
    if meta.mode & 0o111 == 0 || vfs::mount_flags(&d) & vfs::MNT_NOEXEC != 0 {
        return Err(EACCES);
    }
    cred.permission(&meta, super::cred::MAY_EXEC)?;
    // Running a file reads it: its access time (ADR 0162).
    vfs::accessed(&d);
    Ok(d)
}

/// The parsed headers of an ELF file (kept in a buffer owned by the caller).
fn read_headers(file: &Dentry) -> Result<(Vec<u8>, u64), Errno> {
    let size = file.metadata().size;
    let mut first = vec![0u8; (size as usize).min(64)];
    read_exact(file, 0, &mut first)?;
    let hlen = Elf::headers_len(&first).ok_or(ENOEXEC)?;
    if hlen as u64 > size || hlen > 64 * 1024 {
        return Err(ENOEXEC);
    }
    let mut headers = vec![0u8; hlen];
    read_exact(file, 0, &mut headers)?;
    Ok((headers, size))
}

/// Map an ELF file's PT_LOAD segments at `base`; returns the end of the
/// highest segment. Segments are file-backed (paged in on first touch),
/// with the partial page at the end of the file data zeroed past it and an
/// anonymous mapping for the rest of the BSS.
fn map_segments(
    aspace: &mut AddressSpace,
    root: &Arc<Dentry>,
    file: &Arc<Dentry>,
    elf: &Elf<'_>,
    base: u64,
) -> Result<u64, Errno> {
    let name: Arc<str> = crate::fs::vfs::path_seen(file, root).into();
    let mut end = 0u64;
    let mut segments: Vec<_> = elf.program_headers().filter(|p| p.kind == PT_LOAD && p.memsz > 0).collect();
    segments.sort_by_key(|p| p.vaddr);
    for ph in &segments {
        let vaddr = base + ph.vaddr;
        let start = page_floor(vaddr);
        let file_end = vaddr + ph.filesz;
        let mem_end = vaddr + ph.memsz;
        let prot = Prot { read: true, write: ph.flags & PF_W != 0, exec: ph.flags & PF_X != 0 };
        if ph.offset % PAGE_SIZE != vaddr % PAGE_SIZE {
            return Err(ENOEXEC); // gABI requires congruent offsets and addresses.
        }
        if start < end {
            // Shares a page with the previous segment: copy it in eagerly.
            aspace.map(Some(end), page_ceil(mem_end).saturating_sub(end).max(PAGE_SIZE), prot, false).ok();
            copy_segment(aspace, file, ph.offset, vaddr, ph.filesz)?;
        } else {
            if ph.filesz > 0 {
                let len = page_ceil(file_end) - start;
                aspace
                    .map_file(
                        Some(start),
                        len,
                        prot,
                        false,
                        crate::mm::aspace::FileBacking {
                            inode: file.inode.clone(),
                            offset: page_floor(ph.offset),
                            name: Some(name.clone()),
                        },
                        false,
                    )
                    .map_err(|_| ENOEXEC)?;
                // Bytes after the file data in its last page belong to the BSS.
                let tail = page_ceil(file_end).min(mem_end.max(file_end)) - file_end;
                if ph.memsz > ph.filesz && tail > 0 {
                    aspace.write_bytes(file_end, &vec![0u8; tail as usize]).map_err(|_| ENOMEM)?;
                }
            }
            let anon_start = if ph.filesz > 0 { page_ceil(file_end) } else { start };
            if page_ceil(mem_end) > anon_start {
                aspace.map(Some(anon_start), page_ceil(mem_end) - anon_start, prot, false).map_err(|_| ENOEXEC)?;
            }
        }
        end = end.max(page_ceil(mem_end));
    }
    Ok(end)
}

fn copy_segment(aspace: &mut AddressSpace, file: &Dentry, offset: u64, vaddr: u64, len: u64) -> Result<(), Errno> {
    let mut buf = vec![0u8; CHUNK];
    let mut done = 0;
    while done < len {
        let n = ((len - done) as usize).min(CHUNK);
        read_exact(file, offset + done, &mut buf[..n])?;
        aspace.write_bytes(vaddr + done, &buf[..n]).map_err(|_| ENOMEM)?;
        done += n as u64;
    }
    Ok(())
}

/// Where the dynamic loader (PT_INTERP) is placed without randomization:
/// between the mmap area and the stack. With it, it goes at the top of the
/// (moved) mmap area.
const INTERP_BASE: u64 = 0x7FF0_0000_0000;

/// AT_UID, AT_EUID, AT_GID, AT_EGID and AT_SECURE for the new image.
type AuxIds = [u64; 5];

fn aux_ids(c: &super::cred::Cred, secure: bool) -> AuxIds {
    [u64::from(c.ruid), u64::from(c.euid), u64::from(c.rgid), u64::from(c.egid), u64::from(secure)]
}

/// Map a program (and its PT_INTERP dynamic loader, if any) and its stack.
#[allow(clippy::too_many_arguments)]
fn load_program(
    aspace: &mut AddressSpace,
    root: &Arc<Dentry>,
    cwd: &Arc<Dentry>,
    file: &Arc<Dentry>,
    argv: &[&[u8]],
    envp: &[&[u8]],
    execfn: &[u8],
    cred: &super::cred::Cred,
    ids: AuxIds,
    layout: Layout,
) -> Result<(Image, super::Abi), Errno> {
    let (headers, size) = read_headers(file)?;
    let elf = Elf::parse_prefix(&headers, size).map_err(|_| ENOEXEC)?;
    let abi = abi_of(file, &elf)?;
    aspace.mmap_top = layout.mmap_top();
    aspace.stack_top = layout.stack_top();
    let base = if elf.header.kind == ET_DYN { layout.pie_base() } else { 0 };
    let end = map_segments(aspace, root, file, &elf, base)?;
    let brk = if layout.brk { page_ceil(end) + layout.brk_gap() } else { end };
    aspace.brk_start = brk;
    aspace.brk = brk;

    // The dynamic loader named by PT_INTERP runs first (execve(2)).
    let mut interp = None;
    if let Some(ph) = elf.program_headers().find(|p| p.kind == slate_elf::PT_INTERP) {
        let mut name = vec![0u8; (ph.filesz as usize).min(vfs::PATH_MAX)];
        read_exact(file, ph.offset, &mut name)?;
        let name = name.split(|&b| b == 0).next().unwrap_or(&[]);
        let path = core::str::from_utf8(name).map_err(|_| ENOEXEC)?;
        let ld = executable(root, cwd, path, cred).map_err(|e| if e == EACCES { ELIBBAD } else { e })?;
        let (ld_headers, ld_size) = read_headers(&ld)?;
        let ld_elf = Elf::parse_prefix(&ld_headers, ld_size).map_err(|_| ELIBBAD)?;
        if ld_elf.header.kind != ET_DYN {
            return Err(ELIBBAD);
        }
        let ld_base = if layout.maps { free_base(aspace, &ld_elf).ok_or(ENOMEM)? } else { INTERP_BASE };
        map_segments(aspace, root, &ld, &ld_elf, ld_base)?;
        interp = Some((ld_base, ld_base + ld_elf.header.entry));
    }

    let stack_limit =
        super::current().map_or(crate::mm::aspace::STACK_MAX, |p| p.rlimit(super::rlimit::RLIMIT_STACK).cur);
    aspace.map_stack(crate::mm::aspace::stack_size(stack_limit)).map_err(|_| ENOMEM)?;
    let vdso = crate::mm::vdso::map(aspace, layout.vvar()).map_err(|_| ENOMEM)?;
    let interp_base = interp.map_or(0, |(b, _)| b);
    let top = aspace.stack_top - layout.stack_offset();
    let sp = build_stack(aspace, &elf, base, interp_base, vdso, argv, envp, execfn, ids, abi, top)?;
    let entry = interp.map_or(base + elf.header.entry, |(_, e)| e);
    Ok((Image { entry, stack_pointer: sp, bias: base }, abi))
}

/// A base for a position-independent ELF file at the top of the free
/// mapping area.
fn free_base(aspace: &AddressSpace, elf: &Elf<'_>) -> Option<u64> {
    let loads = || elf.program_headers().filter(|p| p.kind == PT_LOAD && p.memsz > 0);
    let low = page_floor(loads().map(|p| p.vaddr).min()?);
    let high = page_ceil(loads().map(|p| p.vaddr + p.memsz).max()?);
    Some(aspace.find_free(high - low)? - low)
}

/// The interface `file` asks for (a non-ELF file is a Linux program; the
/// loader rejects it later).
fn abi_of_file(file: &Dentry) -> Result<super::Abi, Errno> {
    let Ok((headers, size)) = read_headers(file) else { return Ok(super::Abi::Linux) };
    match Elf::parse_prefix(&headers, size) {
        Ok(elf) => abi_of(file, &elf),
        Err(_) => Ok(super::Abi::Linux),
    }
}

/// Largest note segment read when looking for the ABI note.
const MAX_NOTES: u64 = 4096;

/// The interface a program asks for: native if it carries the `Slate` ABI
/// note with a version of at least 1 (ADR 0031), Linux otherwise.
fn abi_of(file: &Dentry, elf: &Elf<'_>) -> Result<super::Abi, Errno> {
    for ph in elf.program_headers().filter(|p| p.kind == slate_elf::PT_NOTE && p.filesz <= MAX_NOTES) {
        let mut data = vec![0u8; ph.filesz as usize];
        read_exact(file, ph.offset, &mut data)?;
        let native = slate_elf::notes(&data, ph.align).any(|n| {
            n.name == slate_abi::NOTE_NAME
                && n.kind == slate_abi::NT_SLATE_ABI
                && n.desc.get(..4).is_some_and(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]) >= 1)
        });
        if native {
            return Ok(super::Abi::Native);
        }
    }
    Ok(super::Abi::Linux)
}

/// Lay out argc, argv, envp, auxv and the strings they point to, top-down
/// from `top`. Returns the initial stack pointer (16-byte aligned,
/// pointing at argc).
#[allow(clippy::too_many_arguments)]
fn build_stack(
    aspace: &mut AddressSpace,
    elf: &Elf<'_>,
    base: u64,
    interp_base: u64,
    vdso: Option<u64>,
    argv: &[&[u8]],
    envp: &[&[u8]],
    execfn: &[u8],
    ids: AuxIds,
    abi: super::Abi,
    top: u64,
) -> Result<u64, Errno> {
    let total: usize = argv.iter().chain(envp).map(|s| s.len() + 1).sum();
    if total > ARG_MAX {
        return Err(E2BIG);
    }
    let mut sp = top;
    let mut push_bytes = |aspace: &mut AddressSpace, bytes: &[u8], nul: bool| -> Result<u64, Errno> {
        sp -= bytes.len() as u64 + u64::from(nul);
        aspace.write_bytes(sp, bytes).map_err(|_| ENOMEM)?;
        if nul {
            aspace.write_bytes(sp + bytes.len() as u64, &[0]).map_err(|_| ENOMEM)?;
        }
        Ok(sp)
    };

    let execfn_ptr = push_bytes(aspace, execfn, true)?;
    let mut env_ptrs = Vec::with_capacity(envp.len());
    for e in envp.iter().rev() {
        env_ptrs.push(push_bytes(aspace, e, true)?);
    }
    env_ptrs.reverse();
    let mut arg_ptrs = Vec::with_capacity(argv.len());
    for a in argv.iter().rev() {
        arg_ptrs.push(push_bytes(aspace, a, true)?);
    }
    arg_ptrs.reverse();
    let platform = push_bytes(aspace, b"x86_64", true)?;
    let mut random = [0u8; 16];
    crate::random::fill(&mut random);
    let random_ptr = push_bytes(aspace, &random, false)?;

    let hwcap = u64::from(crate::arch::cpu::cpuid(1, 0).3);
    let auxv: [(u64, u64); 18] = [
        (AT_PHDR, elf.phdr_vaddr().map_or(0, |v| base + v)),
        (AT_PHENT, slate_elf::PHDR_SIZE as u64),
        (AT_PHNUM, u64::from(elf.header.phnum)),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_BASE, interp_base),
        (AT_FLAGS, 0),
        (AT_ENTRY, base + elf.header.entry),
        (AT_UID, ids[0]),
        (AT_EUID, ids[1]),
        (AT_GID, ids[2]),
        (AT_EGID, ids[3]),
        (AT_SECURE, ids[4]),
        (AT_RANDOM, random_ptr),
        (AT_HWCAP, hwcap),
        (AT_CLKTCK, 100),
        (AT_PLATFORM, platform),
        (AT_RSEQ_FEATURE_SIZE, crate::proc::rseq::FEATURE_SIZE),
        (AT_RSEQ_ALIGN, 32),
    ];
    let mut words: Vec<u64> = Vec::new();
    words.push(argv.len() as u64);
    words.extend(&arg_ptrs);
    words.push(0);
    words.extend(&env_ptrs);
    words.push(0);
    for (k, v) in auxv {
        words.extend([k, v]);
    }
    if let Some(v) = vdso {
        words.extend([AT_SYSINFO_EHDR, v]);
    }
    if abi == super::Abi::Native {
        words.extend([slate_abi::AT_SLATE_ABI, u64::from(slate_abi::VERSION)]);
    }
    words.extend([AT_EXECFN, execfn_ptr, AT_NULL, 0]);

    let mut top = sp & !15;
    if words.len() % 2 == 1 {
        top -= 8; // Keep the final stack pointer 16-byte aligned.
    }
    let start = top - words.len() as u64 * 8;
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    aspace.write_bytes(start, &bytes).map_err(|_| ENOMEM)?;
    Ok(start)
}
