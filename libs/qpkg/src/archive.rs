// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `.qpk` container (ADR 0025, format 2 by ADR 0069): a header, the
//! manifest, the entries, and an Ed25519 signature over the SHA-512
//! digest of every byte before it.
//!
//! Format 2 compresses: a file's contents follow its entry as data
//! records, each at most [`CHUNK`] bytes deflated on its own, so a reader
//! holds one chunk at a time. [`Stream`] reads a package as it arrives, in
//! pieces of any size, and says what it found; nothing is trusted until
//! [`Item::End`], after the signature. Format 1 (entries with their data,
//! uncompressed) is still read.

use alloc::string::String;
use alloc::vec::Vec;

use crate::Error;
use crate::manifest::Manifest;
use crate::sign::{KeyId, Keyring, SecretKey};

const MAGIC: &[u8; 8] = b"SLATEQPK";
const FORMAT_V1: u32 = 1;
const FORMAT: u32 = 2;
const HEADER_LEN: usize = 16;
const REC_MANIFEST: u8 = 1;
const REC_ENTRY: u8 = 2;
const REC_SIGNATURE: u8 = 3;
const REC_DATA: u8 = 4;
/// Size of a signature record's body: key id and signature.
pub const SIGNATURE_LEN: usize = 8 + 64;
/// The most bytes of a file one data record holds, uncompressed.
pub const CHUNK: usize = 1 << 20;
/// The largest record a reader accepts (a format 1 entry holds its whole
/// file).
const MAX_RECORD: u64 = 256 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
}

/// One file, directory or symlink in a package. `data` is a file's
/// contents or a link's target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub kind: Kind,
    pub mode: u32,
    pub data: Vec<u8>,
}

/// A verified package.
#[derive(Clone, Debug)]
pub struct Package {
    pub manifest: Manifest,
    pub entries: Vec<Entry>,
    /// The key that signed it.
    pub signer: KeyId,
}

/// Paths are relative, `/`-separated, without empty, `.` or `..` parts.
pub fn valid_path(p: &str) -> bool {
    !p.is_empty() && p.len() < 4096 && !p.contains('\0') && p.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

fn record(out: &mut Vec<u8>, kind: u8, body: &[u8]) {
    out.push(kind);
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(body);
}

fn kind_byte(k: Kind) -> u8 {
    match k {
        Kind::File => 0,
        Kind::Dir => 1,
        Kind::Symlink => 2,
    }
}

/// Build and sign a package (format 2).
pub fn write(manifest: &Manifest, entries: &[Entry], key: &SecretKey) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&FORMAT.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    record(&mut out, REC_MANIFEST, manifest.to_text().as_bytes());
    for e in entries {
        if !valid_path(&e.path) {
            return Err(Error::Format("bad entry path"));
        }
        let mut body = Vec::with_capacity(e.path.len() + 24);
        body.extend_from_slice(&(e.path.len() as u32).to_le_bytes());
        body.extend_from_slice(e.path.as_bytes());
        body.push(kind_byte(e.kind));
        body.extend_from_slice(&e.mode.to_le_bytes());
        match e.kind {
            Kind::File => body.extend_from_slice(&(e.data.len() as u64).to_le_bytes()),
            Kind::Symlink => body.extend_from_slice(&e.data),
            Kind::Dir => {}
        }
        record(&mut out, REC_ENTRY, &body);
        if e.kind == Kind::File {
            for chunk in e.data.chunks(CHUNK) {
                let mut d = Vec::with_capacity(chunk.len() / 2 + 8);
                d.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
                d.extend_from_slice(&slate_flate::deflate(chunk));
                record(&mut out, REC_DATA, &d);
            }
        }
    }
    out.extend_from_slice(&sign_trailer(&out, key));
    Ok(out)
}

/// The signature record for `signed` bytes.
pub fn sign_trailer(signed: &[u8], key: &SecretKey) -> Vec<u8> {
    let digest = slate_hash::sha512(signed);
    let mut body = Vec::with_capacity(SIGNATURE_LEN);
    body.extend_from_slice(&key.public().id());
    body.extend_from_slice(&key.sign(&digest));
    let mut out = Vec::new();
    record(&mut out, REC_SIGNATURE, &body);
    out
}

/// Check a detached signature record (as in `INDEX.sig`) over `signed`.
pub fn verify_detached(signed: &[u8], trailer: &[u8], keys: &Keyring) -> Result<KeyId, Error> {
    if trailer.len() != 9 + SIGNATURE_LEN || trailer[0] != REC_SIGNATURE {
        return Err(Error::Unsigned);
    }
    if u64::from_le_bytes(trailer[1..9].try_into().unwrap()) != SIGNATURE_LEN as u64 {
        return Err(Error::Unsigned);
    }
    let body = &trailer[9..];
    let id: KeyId = body[..8].try_into().unwrap();
    keys.verify(&id, &slate_hash::sha512(signed), body[8..].try_into().unwrap())?;
    Ok(id)
}

/// What a [`Stream`] found, in order. A file is `File`, its `Data` pieces
/// (as many as it takes, possibly none), then `FileEnd`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    Manifest(alloc::boxed::Box<Manifest>),
    Dir {
        path: String,
        mode: u32,
    },
    Symlink {
        path: String,
        target: Vec<u8>,
    },
    File {
        path: String,
        mode: u32,
        size: u64,
    },
    Data(Vec<u8>),
    FileEnd,
    /// The signature checked out: everything before it is the signer's.
    /// `sha256` and `size` are the whole package's (to check against an
    /// index).
    End {
        signer: KeyId,
        sha256: [u8; 32],
        size: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Header,
    Records,
    /// A file whose data records are still to come: bytes left.
    FileData(u64),
    Done,
}

/// A package read as it arrives (format 1 or 2).
pub struct Stream {
    pending: Vec<u8>,
    state: State,
    format: u32,
    have_manifest: bool,
    signed: slate_hash::Sha512,
    whole: slate_hash::Sha256,
    size: u64,
}

impl Default for Stream {
    fn default() -> Stream {
        Stream::new()
    }
}

impl core::fmt::Debug for Stream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Stream({:?}, {} bytes)", self.state, self.size)
    }
}

impl Stream {
    pub fn new() -> Stream {
        Stream {
            pending: Vec::new(),
            state: State::Header,
            format: 0,
            have_manifest: false,
            signed: slate_hash::Sha512::default(),
            whole: slate_hash::Sha256::default(),
            size: 0,
        }
    }

    /// Take the next bytes of the package; what they complete goes to
    /// `out`. Bytes after the signature are an error.
    pub fn feed(&mut self, bytes: &[u8], keys: &Keyring, out: &mut Vec<Item>) -> Result<(), Error> {
        if self.state == State::Done {
            return if bytes.is_empty() { Ok(()) } else { Err(Error::Format("data after the signature")) };
        }
        self.whole.update(bytes);
        self.size += bytes.len() as u64;
        let mut pending = core::mem::take(&mut self.pending);
        pending.extend_from_slice(bytes);
        let r = self.consume(&pending, keys, out);
        let at = r?;
        pending.drain(..at);
        self.pending = pending;
        Ok(())
    }

    /// Read the whole records in `pending`; how many bytes they took.
    fn consume(&mut self, pending: &[u8], keys: &Keyring, out: &mut Vec<Item>) -> Result<usize, Error> {
        let mut at = 0;
        loop {
            let rest = &pending[at..];
            if self.state == State::Header {
                if rest.len() < HEADER_LEN {
                    break;
                }
                if &rest[..8] != MAGIC {
                    return Err(Error::Format("not a quarry package"));
                }
                self.format = u32::from_le_bytes(rest[8..12].try_into().unwrap());
                if self.format != FORMAT && self.format != FORMAT_V1 {
                    return Err(Error::Format("unsupported package format version"));
                }
                self.signed.update(&rest[..HEADER_LEN]);
                at += HEADER_LEN;
                self.state = State::Records;
                continue;
            }
            if self.state == State::Done {
                if !rest.is_empty() {
                    return Err(Error::Format("data after the signature"));
                }
                break;
            }
            if rest.len() < 9 {
                break;
            }
            let kind = rest[0];
            let len = u64::from_le_bytes(rest[1..9].try_into().unwrap());
            if len > MAX_RECORD {
                return Err(Error::Format("record too large"));
            }
            let len = len as usize;
            if rest.len() < 9 + len {
                break;
            }
            let (head, body) = (&rest[..9], &rest[9..9 + len]);
            if kind != REC_SIGNATURE {
                self.signed.update(head);
                self.signed.update(body);
            }
            let mut items = Vec::new();
            self.record(kind, body, keys, &mut items)?;
            at += 9 + len;
            out.extend(items);
            if self.state == State::Done && at != pending.len() {
                return Err(Error::Format("data after the signature"));
            }
        }
        Ok(at)
    }

    fn record(&mut self, kind: u8, body: &[u8], keys: &Keyring, out: &mut Vec<Item>) -> Result<(), Error> {
        if let State::FileData(left) = self.state {
            if kind != REC_DATA {
                return Err(Error::Format("a file's data is missing"));
            }
            if body.len() < 4 {
                return Err(Error::Format("bad data record"));
            }
            let raw = u32::from_le_bytes(body[..4].try_into().unwrap()) as usize;
            if raw == 0 || raw > CHUNK || raw as u64 > left {
                return Err(Error::Format("bad data record"));
            }
            let (data, _) =
                slate_flate::inflate_raw_limited(&body[4..], raw).map_err(|_| Error::Format("bad compressed data"))?;
            if data.len() != raw {
                return Err(Error::Format("bad compressed data"));
            }
            out.push(Item::Data(data));
            let left = left - raw as u64;
            if left == 0 {
                out.push(Item::FileEnd);
                self.state = State::Records;
            } else {
                self.state = State::FileData(left);
            }
            return Ok(());
        }
        match kind {
            REC_MANIFEST if !self.have_manifest => {
                let text = core::str::from_utf8(body).map_err(|_| Error::Format("manifest is not UTF-8"))?;
                out.push(Item::Manifest(alloc::boxed::Box::new(Manifest::parse(text)?)));
                self.have_manifest = true;
            }
            REC_ENTRY if self.have_manifest => self.entry(body, out)?,
            REC_SIGNATURE => {
                if body.len() != SIGNATURE_LEN {
                    return Err(Error::Format("bad signature record"));
                }
                if !self.have_manifest {
                    return Err(Error::Format("package without a manifest"));
                }
                let id: KeyId = body[..8].try_into().unwrap();
                let digest = core::mem::take(&mut self.signed).finish();
                keys.verify(&id, &digest, body[8..].try_into().unwrap())?;
                let sha256 = core::mem::take(&mut self.whole).finish();
                out.push(Item::End { signer: id, sha256, size: self.size });
                self.state = State::Done;
            }
            _ => return Err(Error::Format("unexpected record")),
        }
        Ok(())
    }

    fn entry(&mut self, body: &[u8], out: &mut Vec<Item>) -> Result<(), Error> {
        let mut r = Bytes { b: body, at: 0 };
        let plen = u32::from_le_bytes(r.take(4)?.try_into().unwrap()) as usize;
        let path = core::str::from_utf8(r.take(plen)?).map_err(|_| Error::Format("path is not UTF-8"))?;
        if !valid_path(path) {
            return Err(Error::Format("bad entry path"));
        }
        let kind = r.take(1)?[0];
        let mode = u32::from_le_bytes(r.take(4)?.try_into().unwrap()) & 0o7777;
        let rest = &body[r.at..];
        let path = String::from(path);
        match kind {
            1 => out.push(Item::Dir { path, mode }),
            2 => out.push(Item::Symlink { path, target: rest.to_vec() }),
            // Format 1: the file's data is the rest of the record.
            0 if self.format == FORMAT_V1 => {
                out.push(Item::File { path, mode, size: rest.len() as u64 });
                if !rest.is_empty() {
                    out.push(Item::Data(rest.to_vec()));
                }
                out.push(Item::FileEnd);
            }
            0 => {
                let size = u64::from_le_bytes(rest.try_into().map_err(|_| Error::Format("bad file entry"))?);
                out.push(Item::File { path, mode, size });
                if size == 0 {
                    out.push(Item::FileEnd);
                } else {
                    self.state = State::FileData(size);
                }
            }
            _ => return Err(Error::Format("bad entry kind")),
        }
        Ok(())
    }

    /// The package ended: it must have been whole and signed.
    pub fn finish(&self) -> Result<(), Error> {
        match self.state {
            State::Done => Ok(()),
            State::Records if self.have_manifest && self.pending.is_empty() => Err(Error::Unsigned),
            _ => Err(Error::Format("truncated package")),
        }
    }
}

struct Bytes<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Bytes<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len()).ok_or(Error::Format("truncated package"))?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }
}

/// Parse and verify a whole package: the signature must be the last
/// record, by a trusted key, over everything before it. Unsigned packages
/// fail.
pub fn read(bytes: &[u8], keys: &Keyring) -> Result<Package, Error> {
    let mut s = Stream::new();
    let mut items = Vec::new();
    s.feed(bytes, keys, &mut items)?;
    s.finish()?;
    let mut manifest = None;
    let mut entries: Vec<Entry> = Vec::new();
    let mut signer = None;
    for it in items {
        match it {
            Item::Manifest(m) => manifest = Some(*m),
            Item::Dir { path, mode } => entries.push(Entry { path, kind: Kind::Dir, mode, data: Vec::new() }),
            Item::Symlink { path, target } => {
                entries.push(Entry { path, kind: Kind::Symlink, mode: 0o777, data: target })
            }
            Item::File { path, mode, size } => {
                entries.push(Entry { path, kind: Kind::File, mode, data: Vec::with_capacity(size as usize) })
            }
            Item::Data(d) => {
                if let Some(e) = entries.last_mut() {
                    e.data.extend_from_slice(&d);
                }
            }
            Item::FileEnd => {}
            Item::End { signer: id, .. } => signer = Some(id),
        }
    }
    Ok(Package {
        manifest: manifest.ok_or(Error::Format("package without a manifest"))?,
        entries,
        signer: signer.ok_or(Error::Unsigned)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Abi;
    use alloc::vec;

    fn key() -> SecretKey {
        SecretKey::from_seed([7; 32])
    }

    fn sample() -> (Manifest, Vec<Entry>) {
        let mut m = Manifest::new("big", "2.0");
        m.abi = Abi::Any;
        // Over two chunks of compressible text, and an empty file.
        let text: Vec<u8> = (0..(CHUNK * 2 + 1234)).map(|i| b"abcdefgh\n"[i % 9]).collect();
        let entries = vec![
            Entry { path: "d".into(), kind: Kind::Dir, mode: 0o755, data: vec![] },
            Entry { path: "d/text".into(), kind: Kind::File, mode: 0o644, data: text },
            Entry { path: "d/empty".into(), kind: Kind::File, mode: 0o600, data: vec![] },
            Entry { path: "d/link".into(), kind: Kind::Symlink, mode: 0o777, data: b"text".to_vec() },
        ];
        (m, entries)
    }

    #[test]
    fn compressed_and_read_in_any_pieces() {
        let (m, entries) = sample();
        let bytes = write(&m, &entries, &key()).unwrap();
        assert!(bytes.len() < CHUNK / 4, "{} bytes", bytes.len());
        let ring = Keyring::new(vec![key().public()]);
        let whole = read(&bytes, &ring).unwrap();
        assert_eq!((whole.manifest, whole.entries.clone()), (m, entries.clone()));
        // Fed a few bytes at a time, the same items, and the end last.
        for piece in [1, 7, 4096] {
            let mut s = Stream::new();
            let mut items = Vec::new();
            for c in bytes.chunks(piece) {
                s.feed(c, &ring, &mut items).unwrap();
            }
            s.finish().unwrap();
            let datas = items.iter().filter(|i| matches!(i, Item::Data(_))).count();
            assert_eq!(datas, 3, "three chunks of the big file");
            assert_eq!(
                items.last(),
                Some(&Item::End {
                    signer: key().public().id(),
                    sha256: slate_hash::sha256(&bytes),
                    size: bytes.len() as u64
                })
            );
        }
        // Cut short: never ends.
        let mut s = Stream::new();
        let mut items = Vec::new();
        s.feed(&bytes[..bytes.len() - 10], &ring, &mut items).unwrap();
        assert!(s.finish().is_err());
        assert!(!items.iter().any(|i| matches!(i, Item::End { .. })));
    }

    #[test]
    fn reads_format_1() {
        let (m, entries) = sample();
        let mut v1 = Vec::new();
        v1.extend_from_slice(MAGIC);
        v1.extend_from_slice(&FORMAT_V1.to_le_bytes());
        v1.extend_from_slice(&0u32.to_le_bytes());
        record(&mut v1, REC_MANIFEST, m.to_text().as_bytes());
        for e in &entries {
            let mut body = Vec::new();
            body.extend_from_slice(&(e.path.len() as u32).to_le_bytes());
            body.extend_from_slice(e.path.as_bytes());
            body.push(kind_byte(e.kind));
            body.extend_from_slice(&e.mode.to_le_bytes());
            body.extend_from_slice(&e.data);
            record(&mut v1, REC_ENTRY, &body);
        }
        let sig = sign_trailer(&v1, &key());
        v1.extend_from_slice(&sig);
        let p = read(&v1, &Keyring::new(vec![key().public()])).unwrap();
        assert_eq!(p.entries, entries);
    }

    #[test]
    fn refuses_data_larger_than_it_says() {
        // A chunk claiming 10 bytes that inflates to 2000.
        let mut m = Manifest::new("bomb", "1");
        m.abi = Abi::Any;
        let mut b = Vec::new();
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&FORMAT.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        record(&mut b, REC_MANIFEST, m.to_text().as_bytes());
        let mut e = Vec::new();
        e.extend_from_slice(&1u32.to_le_bytes());
        e.extend_from_slice(b"f");
        e.push(0);
        e.extend_from_slice(&0o644u32.to_le_bytes());
        e.extend_from_slice(&10u64.to_le_bytes());
        record(&mut b, REC_ENTRY, &e);
        let mut d = 10u32.to_le_bytes().to_vec();
        d.extend_from_slice(&slate_flate::deflate(&[0u8; 2000]));
        record(&mut b, REC_DATA, &d);
        let mut items = Vec::new();
        let r = Stream::new().feed(&b, &Keyring::new(vec![key().public()]), &mut items);
        assert_eq!(r, Err(Error::Format("bad compressed data")));
    }
}
