// SPDX-License-Identifier: MIT OR Apache-2.0

//! Checked against signatures and keys made by GnuPG (tests/fixtures:
//! a test key's, and Arch Linux's release key with the signature of the
//! bootstrap tarball of 2026.10.01).

use super::*;

const RELEASE: &[u8] = include_bytes!("../tests/fixtures/release.txt");
const RELEASE_SIG: &[u8] = include_bytes!("../tests/fixtures/release.txt.sig");
const RELEASE_SIG_256: &[u8] = include_bytes!("../tests/fixtures/release.txt.sha256.sig");
const TEST_KEY: &[u8] = include_bytes!("../tests/fixtures/test-key.pgp");
const ARCH_KEY: &[u8] = include_bytes!("../tests/fixtures/arch-release-key.pgp");
const ARCH_SIG: &[u8] = include_bytes!("../tests/fixtures/arch-bootstrap.sig");

#[test]
fn fingerprints() {
    assert_eq!(Key::parse(ARCH_KEY).unwrap().fingerprint_hex(), "3E80CA1A8B89F69CBA57D98A76A5EF9054449A5C");
    assert_eq!(Key::parse(TEST_KEY).unwrap().fingerprint_hex(), "9E05FB1DAFD4A57DD0D84B3F224C76A1AFC12731");
}

#[test]
fn gnupg_signatures() {
    let key = Key::parse(TEST_KEY).unwrap();
    for sig in [RELEASE_SIG, RELEASE_SIG_256] {
        let s = Signature::parse(sig).unwrap();
        assert_eq!(s.issuer_fingerprint, Some(key.fingerprint));
        assert!(s.created.is_some());
        s.check_bytes(RELEASE, &key).unwrap();
        // A changed document, or another key.
        assert_eq!(s.check_bytes(b"A release, signed for libs/pgp tests!\n", &key), Err(Error::Bad));
        assert_eq!(s.check_bytes(RELEASE, &Key::parse(ARCH_KEY).unwrap()), Err(Error::WrongKey));
    }
    // Fed in pieces.
    let s = Signature::parse(RELEASE_SIG).unwrap();
    let mut h = s.hasher();
    for c in RELEASE.chunks(5) {
        h.update(c);
    }
    s.check(h, &key).unwrap();
}

#[test]
fn arch_release() {
    let s = Signature::parse(ARCH_SIG).unwrap();
    let key = Key::parse(ARCH_KEY).unwrap();
    assert_eq!(s.issuer_fingerprint, Some(key.fingerprint));
    assert_eq!(s.hash_alg, 10);
    // (The tarball itself is too large to keep here; xtask's box workbench
    // checks it on Slate.)
    assert_eq!(s.check_bytes(b"not the tarball", &key), Err(Error::Bad));
}

#[test]
fn our_own() {
    let seed = [7u8; 32];
    let key = Key::parse(&public_key(&seed, 1_790_000_000)).unwrap();
    let sig = sign(b"a test distribution", &seed, 1_790_000_000);
    let s = Signature::parse(&sig).unwrap();
    assert_eq!(s.created, Some(1_790_000_000));
    s.check_bytes(b"a test distribution", &key).unwrap();
    assert_eq!(s.check_bytes(b"another", &key), Err(Error::Bad));
    let other = Key::parse(&public_key(&[8u8; 32], 1_790_000_000)).unwrap();
    assert_eq!(s.check_bytes(b"a test distribution", &other), Err(Error::WrongKey));
}

#[test]
fn malformed() {
    assert!(Signature::parse(b"").is_err());
    assert!(Signature::parse(&RELEASE_SIG[..40]).is_err());
    assert!(Key::parse(&[0x98, 2, 4, 0]).is_err());
    // A signature where a key was expected, and the reverse.
    assert!(Key::parse(RELEASE_SIG).is_err());
    assert!(Signature::parse(&public_key(&[1; 32], 0)).is_err());
    // Every truncation fails cleanly.
    for n in 0..RELEASE_SIG.len() {
        let _ = Signature::parse(&RELEASE_SIG[..n]);
    }
    for n in 0..ARCH_KEY.len().min(60) {
        let _ = Key::parse(&ARCH_KEY[..n]);
    }
}
