// SPDX-License-Identifier: MIT OR Apache-2.0

//! The control device, `/dev/snd/controlCn` (ADR 0184): what the card is,
//! which PCM devices it has, and its mixer elements (volumes and
//! switches), with change events for programs that subscribe.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use slate_alsa::abi::*;

use super::Card;
use crate::abi::linux::errno::*;
use crate::arch::uaccess::{copy_from_user, copy_to_user, read_user, write_user};
use crate::fs::vfs::{self, Metadata, Result};
use crate::fs::{File, O_NONBLOCK, POLLIN};
use crate::sched::wait::WaitQueue;
use crate::sync::IrqSpinLock;

/// What a driver does for an element: read its values, write them
/// (returning whether anything changed).
pub trait ElemOps: Send + Sync {
    fn get(&self, values: &mut [i64]);
    fn put(&self, values: &[i64]) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// On or off, per channel.
    Boolean,
    /// From `min` to `max` in steps of `step` (0: any).
    Integer { min: i64, max: i64, step: i64 },
}

/// A mixer element.
pub struct Elem {
    pub iface: u32,
    pub name: String,
    pub index: u32,
    pub device: u32,
    pub kind: Kind,
    /// Values (channels).
    pub count: u32,
    /// A dB scale (`slate_alsa::tlv`), for volumes.
    pub tlv: Option<[u32; 4]>,
    pub ops: Box<dyn ElemOps>,
}

impl Elem {
    pub fn mixer(name: &str, kind: Kind, count: u32, tlv: Option<[u32; 4]>, ops: Box<dyn ElemOps>) -> Arc<Elem> {
        Arc::new(Elem { iface: ELEM_IFACE_MIXER, name: name.into(), index: 0, device: 0, kind, count, tlv, ops })
    }
}

/// An open control device: its subscription and the events waiting.
pub struct Client {
    events: IrqSpinLock<VecDeque<[u8; CTL_EVENT_SIZE]>>,
    subscribed: AtomicBool,
    wait: WaitQueue,
    count: AtomicU64,
}

/// Tell subscribers element `numid` changed (`mask`: what).
pub fn notify(card: &Card, numid: u32, mask: u32) {
    let Some(e) = card.controls.get(numid as usize - 1) else { return };
    let mut ev = [0u8; CTL_EVENT_SIZE];
    put_u32(&mut ev, CE_TYPE, CTL_EVENT_ELEM);
    put_u32(&mut ev, CE_MASK, mask);
    write_id(&mut ev[CE_ID..CE_ID + ELEM_ID_SIZE], numid, e);
    let clients: Vec<Arc<Client>> = {
        let mut cs = card.clients.lock();
        cs.retain(|c| c.strong_count() > 0);
        cs.iter().filter_map(Weak::upgrade).collect()
    };
    for c in clients.iter().filter(|c| c.subscribed.load(Ordering::Acquire)) {
        let mut q = c.events.lock();
        if q.len() < 256 {
            q.push_back(ev);
        }
        drop(q);
        c.count.fetch_add(1, Ordering::Release);
        c.wait.wake_all();
    }
    crate::fs::poll_notify();
}

/// The card went: its open control devices see ENODEV.
pub(super) fn disconnect(card: &Card) {
    for c in card.clients.lock().iter().filter_map(Weak::upgrade) {
        c.count.fetch_add(1, Ordering::Release);
        c.wait.wake_all();
    }
    crate::fs::poll_notify();
}

pub fn open(card: Arc<Card>, flags: u32) -> Result<Arc<dyn File>> {
    let client = Arc::new(Client {
        events: IrqSpinLock::new(VecDeque::new()),
        subscribed: AtomicBool::new(false),
        wait: WaitQueue::new(),
        count: AtomicU64::new(0),
    });
    card.clients.lock().push(Arc::downgrade(&client));
    Ok(Arc::new(CtlFile { card, client, flags: AtomicU32::new(flags), prefer: AtomicU32::new(0) }))
}

struct CtlFile {
    card: Arc<Card>,
    client: Arc<Client>,
    flags: AtomicU32,
    prefer: AtomicU32,
}

/// Write an element's id (`struct snd_ctl_elem_id`).
fn write_id(b: &mut [u8], numid: u32, e: &Elem) {
    put_u32(b, EID_NUMID, numid);
    put_u32(b, EID_IFACE, e.iface);
    put_u32(b, EID_DEVICE, e.device);
    put_u32(b, EID_SUBDEVICE, 0);
    put_str(b, EID_NAME, EID_NAME_LEN, &e.name);
    put_u32(b, EID_INDEX, e.index);
}

impl CtlFile {
    /// The element an id names: by number, else by interface, name and
    /// index. Returns (numid, element).
    fn find(&self, id: &[u8]) -> Result<(u32, Arc<Elem>)> {
        let numid = get_u32(id, EID_NUMID);
        let c = &self.card.controls;
        if numid != 0 {
            return c.get(numid as usize - 1).map(|e| (numid, e.clone())).ok_or(ENOENT);
        }
        let (iface, name, index) =
            (get_u32(id, EID_IFACE), get_str(id, EID_NAME, EID_NAME_LEN), get_u32(id, EID_INDEX));
        c.iter()
            .enumerate()
            .find(|(_, e)| e.iface == iface && e.name.as_bytes() == name && e.index == index)
            .map(|(i, e)| (i as u32 + 1, e.clone()))
            .ok_or(ENOENT)
    }

    fn card_info(&self, arg: u64) -> Result<u64> {
        let c = &self.card;
        let mut b = [0u8; CARD_INFO_SIZE];
        put_u32(&mut b, CI_CARD, c.index);
        put_str(&mut b, CI_ID, 16, &c.id);
        put_str(&mut b, CI_DRIVER, 16, &c.driver);
        put_str(&mut b, CI_NAME, 32, &c.name);
        put_str(&mut b, CI_LONGNAME, 80, &c.longname);
        put_str(&mut b, CI_MIXERNAME, 80, &c.mixername);
        put_str(&mut b, CI_COMPONENTS, 128, &c.components);
        copy_to_user(arg, &b).map(|_| 0).map_err(|_| EFAULT)
    }

    fn elem_list(&self, arg: u64) -> Result<u64> {
        let mut b = [0u8; ELEM_LIST_SIZE];
        copy_from_user(&mut b, arg).map_err(|_| EFAULT)?;
        let (offset, space, pids) = (get_u32(&b, EL_OFFSET), get_u32(&b, EL_SPACE), get_u64(&b, EL_PIDS));
        let all = &self.card.controls;
        let mut used = 0u32;
        if space > 0 {
            for (i, e) in all.iter().enumerate().skip(offset as usize).take(space as usize) {
                let mut id = [0u8; ELEM_ID_SIZE];
                write_id(&mut id, i as u32 + 1, e);
                copy_to_user(pids + u64::from(used) * ELEM_ID_SIZE as u64, &id).map_err(|_| EFAULT)?;
                used += 1;
            }
        }
        put_u32(&mut b, EL_USED, used);
        put_u32(&mut b, EL_COUNT, all.len() as u32);
        copy_to_user(arg, &b).map(|_| 0).map_err(|_| EFAULT)
    }

    fn elem_info(&self, arg: u64) -> Result<u64> {
        let mut b = [0u8; ELEM_INFO_SIZE];
        copy_from_user(&mut b, arg).map_err(|_| EFAULT)?;
        let (numid, e) = self.find(&b[..ELEM_ID_SIZE])?;
        b.fill(0);
        write_id(&mut b[..ELEM_ID_SIZE], numid, &e);
        let mut access = ELEM_ACCESS_READWRITE;
        if e.tlv.is_some() {
            access |= ELEM_ACCESS_TLV_READ;
        }
        put_u32(&mut b, EI_ACCESS, access);
        put_u32(&mut b, EI_COUNT, e.count);
        match e.kind {
            Kind::Boolean => {
                put_u32(&mut b, EI_TYPE, ELEM_TYPE_BOOLEAN);
                put_u64(&mut b, EI_INT_MIN, 0);
                put_u64(&mut b, EI_INT_MAX, 1);
                put_u64(&mut b, EI_INT_STEP, 0);
            }
            Kind::Integer { min, max, step } => {
                put_u32(&mut b, EI_TYPE, ELEM_TYPE_INTEGER);
                put_u64(&mut b, EI_INT_MIN, min as u64);
                put_u64(&mut b, EI_INT_MAX, max as u64);
                put_u64(&mut b, EI_INT_STEP, step as u64);
            }
        }
        copy_to_user(arg, &b).map(|_| 0).map_err(|_| EFAULT)
    }

    fn elem_rw(&self, arg: u64, write: bool) -> Result<u64> {
        let mut b = alloc::vec![0u8; ELEM_VALUE_SIZE];
        copy_from_user(&mut b, arg).map_err(|_| EFAULT)?;
        let (numid, e) = self.find(&b[..ELEM_ID_SIZE])?;
        let n = e.count.min(128) as usize;
        if write {
            let mut v = alloc::vec![0i64; n];
            for (i, x) in v.iter_mut().enumerate() {
                *x = get_u64(&b, EV_VALUE + 8 * i) as i64;
                let ok = match e.kind {
                    Kind::Boolean => (0..=1).contains(x),
                    Kind::Integer { min, max, .. } => (min..=max).contains(x),
                };
                if !ok {
                    return Err(EINVAL);
                }
            }
            if e.ops.put(&v) {
                notify(&self.card, numid, CTL_EVENT_MASK_VALUE);
            }
        }
        let mut v = alloc::vec![0i64; n];
        e.ops.get(&mut v);
        write_id(&mut b[..ELEM_ID_SIZE], numid, &e);
        for (i, x) in v.iter().enumerate() {
            put_u64(&mut b, EV_VALUE + 8 * i, *x as u64);
        }
        copy_to_user(arg, &b).map(|_| 0).map_err(|_| EFAULT)
    }

    /// `TLV_READ`: `struct snd_ctl_tlv` (numid, length in bytes, then the
    /// words).
    fn tlv_read(&self, arg: u64) -> Result<u64> {
        let numid: u32 = read_user(arg).map_err(|_| EFAULT)?;
        let len: u32 = read_user(arg + 4).map_err(|_| EFAULT)?;
        let e = self.card.controls.get((numid as usize).wrapping_sub(1)).ok_or(ENOENT)?;
        let tlv = e.tlv.ok_or(ENXIO)?;
        let bytes = slate_alsa::tlv::to_bytes(&tlv);
        if (len as usize) < bytes.len() {
            return Err(ENOMEM);
        }
        copy_to_user(arg + 8, &bytes).map(|_| 0).map_err(|_| EFAULT)
    }

    /// `PCM_NEXT_DEVICE`: the next PCM device after the one given (-1:
    /// the first), or -1.
    fn pcm_next(&self, arg: u64) -> Result<u64> {
        let after: i32 = read_user(arg).map_err(|_| EFAULT)?;
        let next = self.card.pcms.iter().map(|p| p.device as i32).filter(|d| *d > after).min().unwrap_or(-1);
        write_user(arg, &next).map(|_| 0).map_err(|_| EFAULT)
    }

    fn pcm_info(&self, arg: u64) -> Result<u64> {
        let mut b = [0u8; PCM_INFO_SIZE];
        copy_from_user(&mut b, arg).map_err(|_| EFAULT)?;
        let (device, subdevice, stream) = (get_u32(&b, PI_DEVICE), get_u32(&b, PI_SUBDEVICE), get_u32(&b, PI_STREAM));
        let p = self.card.pcms.iter().find(|p| p.device == device).ok_or(ENXIO)?;
        let s = p.stream(stream).ok_or(ENOENT)?;
        if subdevice != 0 {
            return Err(ENXIO);
        }
        copy_to_user(arg, &s.info(&self.card)).map(|_| 0).map_err(|_| EFAULT)
    }
}

impl File for CtlFile {
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        if self.card.gone.load(Ordering::Acquire) {
            return Err(ENODEV);
        }
        match cmd {
            CTL_IOCTL_PVERSION => write_user(arg, &CTL_VERSION).map(|_| 0).map_err(|_| EFAULT),
            CTL_IOCTL_CARD_INFO => self.card_info(arg),
            CTL_IOCTL_ELEM_LIST => self.elem_list(arg),
            CTL_IOCTL_ELEM_INFO => self.elem_info(arg),
            CTL_IOCTL_ELEM_READ => self.elem_rw(arg, false),
            CTL_IOCTL_ELEM_WRITE => self.elem_rw(arg, true),
            // One writer at a time is not enforced; locking is accepted.
            CTL_IOCTL_ELEM_LOCK | CTL_IOCTL_ELEM_UNLOCK => {
                let mut id = [0u8; ELEM_ID_SIZE];
                copy_from_user(&mut id, arg).map_err(|_| EFAULT)?;
                self.find(&id).map(|_| 0)
            }
            // Elements of the program's own (alsa-lib's softvol): not
            // offered (GAPS.md).
            CTL_IOCTL_ELEM_ADD | CTL_IOCTL_ELEM_REPLACE | CTL_IOCTL_ELEM_REMOVE => Err(EPERM),
            CTL_IOCTL_SUBSCRIBE_EVENTS => {
                let v: i32 = read_user(arg).map_err(|_| EFAULT)?;
                if v < 0 {
                    let on = i32::from(self.client.subscribed.load(Ordering::Acquire));
                    return write_user(arg, &on).map(|_| 0).map_err(|_| EFAULT);
                }
                self.client.subscribed.store(v != 0, Ordering::Release);
                if v == 0 {
                    self.client.events.lock().clear();
                }
                Ok(0)
            }
            CTL_IOCTL_TLV_READ => self.tlv_read(arg),
            CTL_IOCTL_PCM_NEXT_DEVICE => self.pcm_next(arg),
            CTL_IOCTL_PCM_INFO => self.pcm_info(arg),
            CTL_IOCTL_PCM_PREFER_SUBDEVICE => {
                let v: u32 = read_user(arg).map_err(|_| EFAULT)?;
                self.prefer.store(v, Ordering::Relaxed);
                Ok(0)
            }
            // No hardware-dependent, raw MIDI or UMP devices.
            CTL_IOCTL_HWDEP_NEXT_DEVICE | CTL_IOCTL_RAWMIDI_NEXT_DEVICE | CTL_IOCTL_UMP_NEXT_DEVICE => {
                write_user(arg, &-1i32).map(|_| 0).map_err(|_| EFAULT)
            }
            CTL_IOCTL_POWER_STATE => write_user(arg, &CTL_POWER_D0).map(|_| 0).map_err(|_| EFAULT),
            CTL_IOCTL_POWER => Err(ENOPROTOOPT_CTL),
            _ => super::unknown_ioctl("control", cmd),
        }
    }

    /// Events, 72 bytes each (`struct snd_ctl_event`).
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < CTL_EVENT_SIZE {
            return Err(EINVAL);
        }
        let c = &self.client;
        loop {
            if self.card.gone.load(Ordering::Acquire) {
                return Err(ENODEV);
            }
            if !c.subscribed.load(Ordering::Acquire) {
                return Err(EBADFD);
            }
            {
                let mut q = c.events.lock();
                if !q.is_empty() {
                    let mut n = 0;
                    while n + CTL_EVENT_SIZE <= buf.len() {
                        let Some(e) = q.pop_front() else { break };
                        buf[n..n + CTL_EVENT_SIZE].copy_from_slice(&e);
                        n += CTL_EVENT_SIZE;
                    }
                    return Ok(n);
                }
            }
            if self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0 {
                return Err(EAGAIN);
            }
            if c.wait.wait_until_interruptible(|| !c.events.lock().is_empty() || self.card.gone.load(Ordering::Acquire))
            {
                return Err(EINTR);
            }
        }
    }

    fn poll(&self) -> u16 {
        if self.client.events.lock().is_empty() { 0 } else { POLLIN }
    }

    fn event_count(&self) -> u64 {
        self.client.count.load(Ordering::Acquire)
    }

    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }

    fn set_status_flags(&self, flags: u32) {
        let keep = self.flags.load(Ordering::Relaxed) & !O_NONBLOCK;
        self.flags.store(keep | (flags & O_NONBLOCK), Ordering::Relaxed);
    }

    fn stat(&self) -> Result<Metadata> {
        let rdev = vfs::makedev(SOUND_MAJOR, self.card.index * MINORS_PER_CARD);
        Ok(Metadata { mode: vfs::S_IFCHR | 0o660, rdev, nlink: 1, ..Metadata::default() })
    }
}

/// `CTL_POWER` (setting a power state): not offered.
const ENOPROTOOPT_CTL: crate::abi::linux::errno::Errno = crate::abi::linux::errno::ENOPROTOOPT;
