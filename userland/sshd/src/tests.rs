// SPDX-License-Identifier: MIT OR Apache-2.0

extern crate std;

use super::*;

#[test]
fn base64_round_trip() {
    for n in 0..20 {
        let d: Vec<u8> = (0..n).map(|i| (i * 37) as u8).collect();
        assert_eq!(wire::unbase64(wire::base64(&d, true).as_bytes()).unwrap(), d);
    }
    assert_eq!(wire::base64(b"foobar", true), "Zm9vYmFy");
    assert_eq!(wire::base64(b"fo", true), "Zm8=");
    assert_eq!(wire::base64(b"fo", false), "Zm8");
}

#[test]
fn mpint() {
    let enc = |b: &[u8]| wire::Writer::default().mpint(b).finish();
    // RFC 4251 §5 examples.
    assert_eq!(enc(&[0, 0]), [0, 0, 0, 0]);
    assert_eq!(
        enc(&[0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]),
        [0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]
    );
    assert_eq!(enc(&[0x80]), [0, 0, 0, 2, 0, 0x80]);
}

#[test]
fn x25519_rfc7748() {
    // RFC 7748 §6.1.
    let a: [u8; 32] = hexb("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let b: [u8; 32] = hexb("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    assert_eq!(
        crypto::x25519_public(&a),
        hexb::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    let shared = hexb::<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(crypto::x25519_shared(&a, &crypto::x25519_public(&b)), shared);
    assert_eq!(crypto::x25519_shared(&b, &crypto::x25519_public(&a)), shared);
}

fn hexb<const N: usize>(s: &str) -> [u8; N] {
    let mut o = [0u8; N];
    for i in 0..N {
        o[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    o
}

#[test]
fn chacha_seals_and_opens() {
    let key: [u8; 64] = core::array::from_fn(|i| i as u8);
    let c = crypto::Chacha::new(&key);
    let mut p = std::vec![0, 0, 0, 12, 4, 94, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let plain = p.clone();
    c.seal(7, &mut p);
    assert_ne!(&p[..16], &plain[..]);
    assert_eq!(c.length(7, &p[..4].try_into().unwrap()), 12);
    assert_eq!(c.open(7, &p).unwrap(), &plain[4..]);
    assert!(c.open(8, &p).is_none());
    p[5] ^= 1;
    assert!(c.open(7, &p).is_none());
}

#[test]
fn authorized_keys_and_passwd() {
    let blob = wire::Writer::default().string(b"ssh-ed25519").string(&[7u8; 32]).finish();
    let text = std::format!(
        "# comment\nssh-rsa AAAA x\nfrom=\"10.0.0.1\" ssh-ed25519 {} me@host\n",
        wire::base64(&blob, true)
    );
    assert_eq!(auth::authorized_blobs(&text), std::vec![blob]);
    let u = auth::parse_passwd("root:x:0:0:root:/root:/bin/sh\nbob:x:1000:100::/home/bob:\n", "bob").unwrap();
    assert_eq!((u.uid, u.gid, u.home.as_str(), u.shell.as_str()), (1000, 100, "/home/bob", "/bin/sh"));
    assert_eq!(auth::shadow_hash("root::1:::\nbob:$6$x$y:1:::\n", "root").as_deref(), Some(""));
    assert!(!auth::password_ok("", b""));
    assert!(!auth::password_ok("!", b"x"));
}

#[test]
fn publickey_signature_checks() {
    use ed25519_dalek::Signer;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let blob = wire::Writer::default().string(b"ssh-ed25519").string(&sk.verifying_key().to_bytes()).finish();
    let user = auth::User {
        name: "bob".into(),
        uid: 1,
        gid: 1,
        home: "/home/bob".into(),
        shell: "/bin/sh".into(),
        expired: false,
    };
    let sid = [3u8; 32];
    let signed = wire::Writer::default()
        .string(&sid)
        .byte(50)
        .string(b"bob")
        .string(b"ssh-connection")
        .string(b"publickey")
        .bool(true)
        .string(b"ssh-ed25519")
        .string(&blob)
        .finish();
    let sig = wire::Writer::default().string(b"ssh-ed25519").string(&sk.sign(&signed).to_bytes()).finish();
    let req = |with_sig: bool, sig: &[u8]| {
        let mut w = wire::Writer::default();
        w.string(b"bob")
            .string(b"ssh-connection")
            .string(b"publickey")
            .bool(with_sig)
            .string(b"ssh-ed25519")
            .string(&blob);
        if with_sig {
            w.string(sig);
        }
        w.finish()
    };
    let keys = std::format!("ssh-ed25519 {}\n", wire::base64(&blob, true));
    let find = |n: &str| (n == "bob").then(|| user.clone());
    let read = |p: &str| (p == "/home/bob/.ssh/authorized_keys").then(|| keys.clone());
    let t = &[String::from(".ssh/authorized_keys")];
    assert!(matches!(auth::decide(&req(false, &[]), &sid, t, &find, &read), auth::Outcome::KeyAcceptable { .. }));
    assert_eq!(auth::decide(&req(true, &sig), &sid, t, &find, &read), auth::Outcome::Success(user.clone()));
    let mut bad = sig.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(auth::decide(&req(true, &bad), &sid, t, &find, &read), auth::Outcome::Failure);
    assert_eq!(auth::decide(&req(true, &sig), &[4u8; 32], t, &find, &read), auth::Outcome::Failure);
}

#[test]
fn password_and_its_change() {
    // RFC 4252 §8: FALSE and the password, or TRUE, the old and the new.
    let user = auth::User {
        name: "bob".into(),
        uid: 1,
        gid: 1,
        home: "/home/bob".into(),
        shell: "/bin/sh".into(),
        expired: false,
    };
    let hash = slate_coreutils::crypt::crypt(b"old", b"$6$saltsalt").unwrap();
    let shadow = std::format!("bob:{hash}:19000:0:99999:7:::\n");
    let find = |n: &str| (n == "bob").then(|| user.clone());
    let read = |p: &str| (p == "/etc/shadow").then(|| shadow.clone());
    let req = |change: bool, pw: &[u8], new: &[u8]| {
        let mut w = wire::Writer::default();
        w.string(b"bob").string(b"ssh-connection").string(b"password").bool(change).string(pw);
        if change {
            w.string(new);
        }
        w.finish()
    };
    let decide = |m: &[u8]| auth::decide(m, &[0u8; 32], &[], &find, &read);
    assert_eq!(decide(&req(false, b"old", b"")), auth::Outcome::Success(user.clone()));
    assert_eq!(decide(&req(false, b"bad", b"")), auth::Outcome::Failure);
    assert_eq!(
        decide(&req(true, b"old", b"new")),
        auth::Outcome::Change { user: user.clone(), old: b"old".to_vec(), new: b"new".to_vec() }
    );
    assert_eq!(decide(&req(true, b"bad", b"new")), auth::Outcome::Failure);
    assert_eq!(decide(&req(true, b"old", b"")), auth::Outcome::Failure);
    let v = session::Verdict::ChangeRequest(session::EXPIRED_PROMPT.into());
    assert_eq!(session::Verdict::decode(&v.encode()), Some(v));
}

#[test]
fn mlkem768_round_trip() {
    use ml_kem::{Decapsulate, KeyExport};
    let dk = ml_kem::DecapsulationKey768::from_seed(ml_kem::Seed::from([5u8; 64]));
    let ek = dk.encapsulation_key().to_bytes();
    assert_eq!(ek.len(), crypto::MLKEM_EK);
    let (ct, shared) = crypto::mlkem768_encapsulate(&ek, &[7u8; 32]).unwrap();
    assert_eq!(ct.len(), crypto::MLKEM_CT);
    let ct = ml_kem::Ciphertext::<ml_kem::MlKem768>::try_from(ct.as_slice()).unwrap();
    assert_eq!(<[u8; 32]>::from(dk.decapsulate(&ct)), shared);
    // A key of the wrong size, or one that fails the modulus check.
    assert!(crypto::mlkem768_encapsulate(&ek[1..], &[7u8; 32]).is_none());
    assert!(crypto::mlkem768_encapsulate(&[0xff; crypto::MLKEM_EK], &[7u8; 32]).is_none());
}

#[test]
fn sftp_requests() {
    use sftp::*;
    let dir = std::env::temp_dir().join(std::format!("slate-sftp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let home = dir.to_str().unwrap().as_bytes().to_vec();
    let mut s = Server::new(&home);
    let req = |kind: u8, id: u32, f: &dyn Fn(&mut wire::Writer)| {
        let mut w = wire::Writer::new(kind);
        w.u32(id);
        f(&mut w);
        w.finish()
    };
    let status = |reply: &[u8]| {
        assert_eq!(reply[0], 101, "not a STATUS: {reply:?}");
        u32::from_be_bytes(reply[5..9].try_into().unwrap())
    };
    // INIT → VERSION 3 with the extensions.
    let v = s.request(&[1, 0, 0, 0, 3]).unwrap();
    assert_eq!(&v[..5], &[2, 0, 0, 0, 3]);
    assert!(v.windows(24).any(|w| w == b"posix-rename@openssh.com"));
    // OPEN (write, create, truncate), WRITE, CLOSE.
    let h = s
        .request(&req(3, 1, &|w| {
            w.string(b"f.txt").u32(2 | 8 | 0x10).u32(4).u32(0o640);
        }))
        .unwrap();
    assert_eq!(h[0], 102);
    let handle = wire::Reader::new(&h[5..]).string().unwrap().to_vec();
    assert_eq!(
        status(
            &s.request(&req(6, 2, &|w| {
                w.string(&handle).u64(0).string(b"hello sftp\n");
            }))
            .unwrap()
        ),
        FX_OK
    );
    assert_eq!(
        status(
            &s.request(&req(4, 3, &|w| {
                w.string(&handle);
            }))
            .unwrap()
        ),
        FX_OK
    );
    assert_eq!(std::fs::read(dir.join("f.txt")).unwrap(), b"hello sftp\n");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(dir.join("f.txt")).unwrap().permissions().mode() & 0o777, 0o640);
    // STAT: size 11 and the mode.
    let a = s
        .request(&req(17, 4, &|w| {
            w.string(b"f.txt");
        }))
        .unwrap();
    assert_eq!(a[0], 105);
    let mut r = wire::Reader::new(&a[5..]);
    let flags = r.u32().unwrap();
    assert_eq!(flags & 1, 1);
    assert_eq!(r.u64().unwrap(), 11);
    // READ past the end is EOF.
    let h = s
        .request(&req(3, 5, &|w| {
            w.string(b"f.txt").u32(1).u32(0);
        }))
        .unwrap();
    let handle = wire::Reader::new(&h[5..]).string().unwrap().to_vec();
    let d = s
        .request(&req(5, 6, &|w| {
            w.string(&handle).u64(6).u32(100);
        }))
        .unwrap();
    assert_eq!(d[0], 103);
    assert_eq!(wire::Reader::new(&d[5..]).string().unwrap(), b"sftp\n");
    assert_eq!(
        status(
            &s.request(&req(5, 7, &|w| {
                w.string(&handle).u64(11).u32(100);
            }))
            .unwrap()
        ),
        FX_EOF
    );
    // RENAME onto an existing file fails; posix-rename replaces it.
    std::fs::write(dir.join("g.txt"), b"g").unwrap();
    assert_eq!(
        status(
            &s.request(&req(18, 8, &|w| {
                w.string(b"f.txt").string(b"g.txt");
            }))
            .unwrap()
        ),
        FX_FAILURE
    );
    assert_eq!(
        status(
            &s.request(&req(200, 9, &|w| {
                w.string(b"posix-rename@openssh.com").string(b"f.txt").string(b"g.txt");
            }))
            .unwrap()
        ),
        FX_OK
    );
    assert_eq!(std::fs::read(dir.join("g.txt")).unwrap(), b"hello sftp\n");
    // MKDIR, OPENDIR/READDIR, RMDIR; REALPATH and expand-path of ".".
    assert_eq!(
        status(
            &s.request(&req(14, 10, &|w| {
                w.string(b"sub").u32(0);
            }))
            .unwrap()
        ),
        FX_OK
    );
    let h = s
        .request(&req(11, 11, &|w| {
            w.string(b".");
        }))
        .unwrap();
    let handle = wire::Reader::new(&h[5..]).string().unwrap().to_vec();
    let n = s
        .request(&req(12, 12, &|w| {
            w.string(&handle);
        }))
        .unwrap();
    assert_eq!(n[0], 104);
    assert_eq!(u32::from_be_bytes(n[5..9].try_into().unwrap()), 4); // . .. g.txt sub
    assert_eq!(
        status(
            &s.request(&req(12, 13, &|w| {
                w.string(&handle);
            }))
            .unwrap()
        ),
        FX_EOF
    );
    assert_eq!(
        status(
            &s.request(&req(15, 14, &|w| {
                w.string(b"sub");
            }))
            .unwrap()
        ),
        FX_OK
    );
    let p = s
        .request(&req(16, 15, &|w| {
            w.string(b"sub/../g.txt");
        }))
        .unwrap();
    assert_eq!(wire::Reader::new(&p[9..]).string().unwrap(), [home.as_slice(), b"/g.txt"].concat());
    let p = s
        .request(&req(200, 16, &|w| {
            w.string(b"expand-path@openssh.com").string(b"~");
        }))
        .unwrap();
    assert_eq!(wire::Reader::new(&p[9..]).string().unwrap(), home.as_slice());
    // REMOVE, then STAT says no such file; a bad handle fails.
    assert_eq!(
        status(
            &s.request(&req(13, 17, &|w| {
                w.string(b"g.txt");
            }))
            .unwrap()
        ),
        FX_OK
    );
    assert_eq!(
        status(
            &s.request(&req(17, 18, &|w| {
                w.string(b"g.txt");
            }))
            .unwrap()
        ),
        FX_NO_SUCH_FILE
    );
    assert_eq!(
        status(
            &s.request(&req(4, 19, &|w| {
                w.string(b"zzzz");
            }))
            .unwrap()
        ),
        FX_FAILURE
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn session_groups_are_the_users() {
    let group = "root:x:0:\nwheel:x:10:root,alex\nseat:x:64:greeter,alex\nalex:x:1000:\nother:x:5:alexx\n";
    assert_eq!(session::session_groups(group, "alex", 1000), [1000, 10, 64]);
    assert_eq!(session::session_groups(group, "root", 0), [0, 10]);
    assert_eq!(session::session_groups("", "nobody", 65534), [65534]);
}
