// SPDX-License-Identifier: MIT OR Apache-2.0

extern crate std;

use std::vec::Vec;

use super::*;

fn hex(parts: &[&str]) -> Vec<u8> {
    let s: std::string::String = parts.concat();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn key() -> [u8; KEY_BYTES] {
    core::array::from_fn(|i| i as u8)
}

fn pattern() -> Vec<u8> {
    (0..512).map(|i| (i % 251) as u8).collect()
}

/// Sector 5 and sector 2^32 + 2 under the key 00 01 .. 3f, from Python's
/// `cryptography` (OpenSSL's AES-XTS).
#[test]
fn xts_matches_openssl() {
    let x = Xts::new(&key());
    for (n, want) in [
        (
            5u64,
            hex(&[
                "f87ca2f29b117c1b024a6ec8e8c5994e76f7d16b43eed21e6936126969e00dab9d57dfb999d8d20535e3b2b7a51fab52",
                "dc4f54b7080d50b48a54ca22ff3849f3a47cd92ec842f1c18506001e0531e6c83b8ee819357591998fb8eaf9101b7740",
                "6131c00457f67b8e979f97e7af3e0535203a52bffb542cfa6899d1e8231ca3422867ac49ad3e085f3f82644c85982684",
                "3b533724692ded303614fd64fb050acf50f3944cf476e3772cb2fef45d4ba4fd30c72076652a6ce2123786675d53e055",
                "34b648ece6ffaf2be0ab650c4648ff827c5d6d723b7d20916186af4b8be634e0e8a7e162da34a010af7c594938315806",
                "2a8ab6a60123d0eeb0e4c5321ae568bdc5d8ea3dcc6a0f6bac882e1162a41e4dfa255f1edfaaa10fc4b8483645da74e9",
                "0b11a77edb9e433f634820f64063b105a7acc2cde71cf713369dc4ab6e7f56200f3e718d9e6d00e9beb0f977cc5d2a52",
                "9147afb8e9191115ab35fece7f8a134043746aed1a7a690f1dc4e13b83deec87e85b856f6158200d6949b3bb387c859c",
                "91eaf24faf472cd364d46eaf61136d38ff7ee62f03a873bb56c21bb13b6d1e36026c98e31706a8256eabeab58ba5f332",
                "873ddcc98f80b48d1cd0ba0cf234b068e034a94aea84842f8230d9e6dab7a54e387c6c248257e65bcc50604a5f20a80a",
                "115d5f4afb6c4f525cff6ea7459c89b26927d1f8c47275687eb28f7518a5a768",
            ]),
        ),
        (
            4_294_967_298,
            hex(&[
                "f67763e5db400e54b5fe98178f6ec31dfd40d4f0cf963a5276b95e430813704f8abedd90904a586f8c166901eda5e24b",
                "b9f2f776021db66f6b7c38ef8e010c7ab7cb4b2407eb47afbc679dac03f9ba6e68875c5c205374e188a481cc0083bc4c",
                "d689b687dbd2be1d74b10322c6dd23cc8bb03c540adf542836a32666fd6f5fd1968787da23f45534169394bdca1697d8",
                "71159314abb5aa175b8d47deead76600faf518bc989eaba97798e3b98e002d877645eb47af0857971676d8822e9257ab",
                "ad2d8641e6de3aebd019d1b121d2a28fb42467e07e06db8c0d0882fa7ef6d1215ed871fa1be3d3ef9a569a05bd286179",
                "b2b176acfa16b44bfee21f8f001658e54da67f13564e053448158896a76e5699f9418f91e29b7340049c1f55b7ee9015",
                "4745044091075ae7ae0b55a7158a85dfc8c54bf018ab7b03f586692e413e55040222b271cf54d56f6a867c214c4676d0",
                "5b98e3d3b131697fe7b474304f02c3e642dc7a37855bc9ceca4e83e1bebc5128350b695a318a79bf2ee7e4ddbbc40b5a",
                "af91c57b3c769b8cba4e8da4d96dbbde22cf4973bdf6a41f0acb6025eddc5ac5d4720c8249d8ac9f10334409995bd592",
                "f7eaf4e386288d8cfa8a582db2b194844c09ce09d42276ef4b695e80d1dc1d0dcafbd3f2bf76afa3f595c82c429a4cc6",
                "2783286f3ef6b388386a71849f59886e1cbd494ef4639e2ff6f15c8c0270fe1f",
            ]),
        ),
    ] {
        let mut s = pattern();
        x.encrypt(n, &mut s);
        assert_eq!(s, want, "sector {n}");
        x.decrypt(n, &mut s);
        assert_eq!(s, pattern());
    }
}

/// IEEE 1619-2007 Annex B, vector 10 (XTS-AES-256, data unit 0xff).
#[test]
fn xts_ieee_vector_10() {
    let mut k = [0u8; KEY_BYTES];
    k[..32].copy_from_slice(&hex(&["2718281828459045235360287471352662497757247093699959574966967627"]));
    k[32..].copy_from_slice(&hex(&["3141592653589793238462643383279502884197169399375105820974944592"]));
    let mut data: Vec<u8> = (0..512).map(|i| i as u8).collect();
    Xts::new(&k).encrypt(0xff, &mut data);
    assert_eq!(
        data,
        hex(&[
            "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b5d31e276f8fe4a8d66b317f9ac683f44",
            "680a86ac35adfc3345befecb4bb188fd5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0",
            "c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca2a3e7a7d7df7b10355165c8b9a6d0a7d",
            "e8b062c4500dc4cd120c0f7418dae3d0b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f",
            "93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec583e9645e07b8d9670655ba5bbcfecc6",
            "dc3966380ad8fecb17b6ba02469a020a84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1",
            "505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae9be69a2ffeceb1bec9de244fbe15992b",
            "11b77c040f12bd8f6a975a44a0f90c29a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac",
            "6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f645e8b7e9bfdef33943054ff84011493",
            "c27b3429eaedb4ed5376441a77ed43851ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa",
            "773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151",
        ])
    );
}

#[test]
fn consecutive_sectors() {
    let x = Xts::new(&key());
    let mut two: Vec<u8> = pattern().into_iter().chain(pattern()).collect();
    x.encrypt(5, &mut two);
    let mut one = pattern();
    x.encrypt(6, &mut one);
    assert_eq!(&two[512..], &one[..]);
}

/// Small costs keep the test quick; the format and the slot logic are the
/// same.
const QUICK: Params = Params { memory_kib: 64, passes: 1, lanes: 1 };

#[test]
fn header_and_slots() {
    let mut memory = std::vec![Block::default(); QUICK.blocks()];
    let master = key();
    let mut h = Header::new(1 << 21, [9; 16]);
    h.slots[0] = Some(new_slot(&master, b"correct horse", [1; 32], QUICK, &mut memory).unwrap());
    h.slots[2] = Some(new_slot(&master, b"recovery", [2; 32], QUICK, &mut memory).unwrap());
    let bytes = h.to_bytes();
    assert!(is_encrypted(&bytes));
    let back = Header::parse(&bytes).unwrap();
    assert_eq!(back, h);
    assert_eq!((back.data_offset, back.data_sectors), (2048, (1 << 21) - 2048));
    assert_eq!(back.unlock(b"correct horse", &mut memory), Ok(master));
    assert_eq!(back.unlock(b"recovery", &mut memory), Ok(master));
    assert_eq!(back.unlock(b"wrong", &mut memory), Err(Error::WrongPassword));
    assert_eq!(Header::parse(&[0u8; HEADER_BYTES]), Err(Error::NotEncrypted));
    // Too little memory is an error, not a wrong password.
    let mut small = std::vec![Block::default(); 8];
    assert_eq!(back.unlock(b"correct horse", &mut small), Err(Error::Memory));
    // In two halves: the derived key opens its own slot only.
    let slot = back.slots[2].unwrap();
    let kek = slot_key(&slot, b"recovery", &mut memory).unwrap();
    assert_eq!(unwrap_slot(&slot, &kek), Ok(master));
    assert_eq!(unwrap_slot(&back.slots[0].unwrap(), &kek), Err(Error::WrongPassword));
}

/// The Argon2id we build against RFC 9106 §5.3's test vector (which uses
/// a secret and associated data; the format's derivation uses neither).
#[test]
fn argon2id_rfc9106() {
    let params = argon2::ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(argon2::AssociatedData::new(&[4; 12]).unwrap())
        .output_len(32)
        .build()
        .unwrap();
    let a =
        argon2::Argon2::new_with_secret(&[3; 8], argon2::Algorithm::Argon2id, argon2::Version::V0x13, params).unwrap();
    let mut memory = std::vec![Block::default(); 32];
    let mut tag = [0u8; 32];
    a.hash_password_into_with_memory(&[1; 32], &[2; 16], &mut tag, &mut memory).unwrap();
    assert_eq!(tag.to_vec(), hex(&["0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"]));
}

#[repr(C, align(64))]
struct Aligned([u8; 8192]);

#[test]
fn blocks_view() {
    let mut a = std::boxed::Box::new(Aligned([0; 8192]));
    assert_eq!(blocks_from_bytes(&mut a.0).map(|b| b.len()), Some(8));
    assert!(blocks_from_bytes(&mut a.0[8..]).is_none(), "misaligned");
}

/// How long the default derivation takes (`cargo test --release -- --ignored`).
#[test]
#[ignore]
fn default_cost() {
    let mut memory = std::vec![Block::default(); Params::DEFAULT.blocks()];
    let t = std::time::Instant::now();
    derive(b"password", &[7; 32], Params::DEFAULT, &mut memory).unwrap();
    std::println!("Argon2id 64 MiB x3: {:?}", t.elapsed());
}

#[test]
fn damaged_header_falls_back_to_its_copy() {
    let mut mem = std::vec![Block::default(); QUICK.blocks()];
    let mut h = Header::new(10_000, [9; 16]);
    h.slots[0] = Some(new_slot(&key(), b"pw", [1; 32], QUICK, &mut mem).unwrap());
    let good = h.to_bytes();
    assert_eq!(Header::parse(&good).unwrap(), h);
    // One flipped bit in a slot: the CRC catches it, the copy is used.
    let mut bad = good;
    bad[200] ^= 1;
    assert_eq!(Header::parse(&bad), Err(Error::Damaged));
    assert_eq!(Header::parse_either(&bad, &good).unwrap(), h);
    // The first copy overwritten entirely: the copy too.
    assert_eq!(Header::parse_either(&[0u8; HEADER_BYTES], &good).unwrap(), h);
    // Both gone.
    assert_eq!(Header::parse_either(&bad, &[0u8; HEADER_BYTES]), Err(Error::Damaged));
    assert_eq!(Header::parse_either(&[0u8; HEADER_BYTES], &[0u8; HEADER_BYTES]), Err(Error::NotEncrypted));
    // A header from before the CRC (flags 0) still parses.
    let mut old = good;
    old[48..56].fill(0);
    old[200] ^= 1;
    assert!(Header::parse(&old).is_ok());
}

#[test]
fn recovery_keys() {
    let written = recovery_key(&[0xA5; 20]);
    let text = core::str::from_utf8(&written).unwrap();
    assert_eq!(text.len(), 39);
    assert_eq!(text.matches('-').count(), 7);
    assert!(text.split('-').all(|g| g.len() == 4));
    let n = normalize_recovery_key(&written).unwrap();
    // Typed in lower case, without dashes, with O for 0 and l for 1.
    let typed: Vec<u8> = text
        .bytes()
        .filter(|&c| c != b'-')
        .map(|c| match c {
            b'0' => b'o',
            b'1' => b'l',
            c => c.to_ascii_lowercase(),
        })
        .collect();
    assert_eq!(normalize_recovery_key(&typed), Some(n));
    assert_eq!(normalize_recovery_key(b"too short"), None);
    assert_eq!(normalize_recovery_key(b"UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU"), None);
    // Different bytes, different keys.
    assert_ne!(recovery_key(&[0x5A; 20]), written);

    // A header with a password slot and a recovery slot: each opens it.
    let mut mem = std::vec![Block::default(); Params::RECOVERY.blocks()];
    let quick_recovery = |master: &[u8; KEY_BYTES], mem: &mut [Block]| {
        new_slot(master, &n, [3; 32], QUICK, mem).map(|s| Slot { kind: SlotKind::RecoveryKey, ..s })
    };
    let mut h = Header::new(10_000, [1; 16]);
    h.slots[0] = Some(new_slot(&key(), b"secret", [2; 32], QUICK, &mut mem).unwrap());
    h.slots[2] = Some(quick_recovery(&key(), &mut mem).unwrap());
    let h = Header::parse(&h.to_bytes()).unwrap();
    assert_eq!(h.slots[2].unwrap().kind, SlotKind::RecoveryKey);
    assert_eq!(h.free_slot(), Some(1));
    assert_eq!(h.unlock_slot(b"secret", &mut mem).unwrap(), (0, key()));
    assert_eq!(h.unlock_slot(&typed, &mut mem).unwrap(), (2, key()));
    assert_eq!(h.unlock_slot(b"nope", &mut mem), Err(Error::WrongPassword));
    // The real thing: a recovery slot at its own costs.
    let s = new_slot_of(SlotKind::RecoveryKey, &key(), &written, [4; 32], &mut mem).unwrap();
    assert_eq!((s.kind, s.params), (SlotKind::RecoveryKey, Params::RECOVERY));
    assert_eq!(open_slot(&s, &n, &mut mem).unwrap(), key());
}

#[test]
fn wipe_zeroes() {
    let mut b = [7u8; 64];
    wipe(&mut b);
    assert_eq!(b, [0; 64]);
}

#[test]
fn aesni_matches_software() {
    if !aesni::available() {
        std::eprintln!("no AES-NI here; skipped");
        return;
    }
    let soft = Xts::with_aesni(&key(), false);
    let ni = Xts::with_aesni(&key(), true);
    assert!(ni.accelerated() && !soft.accelerated());
    let plain = pattern();
    let (mut a, mut b) = (plain.clone(), plain.clone());
    soft.encrypt(1234, &mut a);
    ni.encrypt(1234, &mut b);
    assert_eq!(a, b, "AES-NI and software XTS differ");
    ni.decrypt(1234, &mut b);
    assert_eq!(b, plain);
    // Other keys, other sectors.
    let k2: [u8; KEY_BYTES] = core::array::from_fn(|i| (i * 37 + 11) as u8);
    let (s2, n2) = (Xts::with_aesni(&k2, false), Xts::with_aesni(&k2, true));
    let (mut a, mut b) = (plain.clone(), plain.clone());
    s2.decrypt(u64::MAX - 3, &mut a);
    n2.decrypt(u64::MAX - 3, &mut b);
    assert_eq!(a, b);
}

#[test]
fn slot_owner_and_kernel_wrap() {
    let mut mem = std::vec![Block::default(); QUICK.blocks()];
    let master = key();
    let mut s = new_slot(&master, b"pw", [7; 32], QUICK, &mut mem).unwrap();
    assert_eq!(s.owner, None);
    s.owner = Some(1000);
    let mut h = Header::new(1 << 20, [1; 16]);
    h.slots[2] = Some(s);
    let back = Header::parse(&h.to_bytes()).unwrap();
    assert_eq!(back.slots[2].unwrap().owner, Some(1000));
    // The two halves (Argon2id in user space, the wrap in the kernel) make
    // a slot the password opens.
    let kek = new_slot_key(b"new", &[9; 32], QUICK, &mut mem).unwrap();
    let wrapped = wrap(&master, &kek).unwrap();
    let t = Slot { kind: SlotKind::Password, params: QUICK, salt: [9; 32], wrapped, owner: Some(1000) };
    assert_eq!(open_slot(&t, b"new", &mut mem).unwrap(), master);
}
