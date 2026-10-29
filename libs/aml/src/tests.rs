// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hand-assembled AML (encodings from ACPI 6.5 chapter 20), one test per
//! area: data, methods and control flow, the namespace, fields over a
//! region, packages, _OSI, recovery while loading.

use std::collections::HashMap;
use std::vec;
use std::vec::Vec;

use crate::{Address, Error, Host, Interpreter, Object, Value};

#[derive(Default)]
struct Mem {
    bytes: HashMap<u64, u8>,
    notified: Vec<(std::string::String, u64)>,
}

impl Host for Mem {
    fn read(&mut self, at: Address, width: u8) -> Result<u64, Error> {
        let Address::Memory(a) = at else { return Err(Error::Host("not memory")) };
        Ok((0..u64::from(width / 8)).fold(0, |v, i| v | u64::from(*self.bytes.get(&(a + i)).unwrap_or(&0)) << (8 * i)))
    }

    fn write(&mut self, at: Address, width: u8, value: u64) -> Result<(), Error> {
        let Address::Memory(a) = at else { return Err(Error::Host("not memory")) };
        for i in 0..u64::from(width / 8) {
            self.bytes.insert(a + i, (value >> (8 * i)) as u8);
        }
        Ok(())
    }

    fn notify(&mut self, path: &str, value: u64) {
        self.notified.push((path.into(), value));
    }
}

/// A PkgLength (§20.2.4) and the body it covers.
fn pkg(body: &[u8]) -> Vec<u8> {
    let n = body.len();
    let mut out = if n < 63 {
        vec![(n + 1) as u8]
    } else if n + 2 < 1 << 12 {
        let l = n + 2;
        vec![0x40 | (l & 0xF) as u8, (l >> 4) as u8]
    } else {
        let l = n + 3;
        vec![0x80 | (l & 0xF) as u8, (l >> 4) as u8, (l >> 12) as u8]
    };
    out.extend_from_slice(body);
    out
}

/// A definition block around `body` (§5.2.11.1), revision `rev`.
fn table(body: &[u8], rev: u8) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(b"DSDT");
    t.extend_from_slice(&((36 + body.len()) as u32).to_le_bytes());
    t.push(rev);
    t.push(0);
    t.extend_from_slice(b"SLATE SLATETST");
    t.extend_from_slice(&[0; 12]);
    t.extend_from_slice(body);
    t
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn load(body: &[u8]) -> Interpreter<Mem> {
    let mut i = Interpreter::new(Mem::default());
    i.load(&table(body, 2)).unwrap();
    assert!(i.problems().is_empty(), "{:?}", i.problems());
    i
}

fn int(i: &mut Interpreter<Mem>, path: &str, args: Vec<Value>) -> u64 {
    i.evaluate(path, args).unwrap().as_int().unwrap()
}

#[test]
fn names_methods_and_arithmetic() {
    // Name(FOO, 5); Method(BAR, 1) { Return(Add(Arg0, FOO)) }
    let body = cat(&[
        &[0x08],
        b"FOO_",
        &[0x0A, 5],
        &[0x14],
        &pkg(&cat(&[b"BAR_", &[0x01, 0xA4, 0x72, 0x68], b"FOO_", &[0x00]])),
    ]);
    let mut i = load(&body);
    assert_eq!(int(&mut i, "\\BAR", vec![Value::Integer(3)]), 8);
    assert_eq!(int(&mut i, "\\FOO", vec![]), 5);
}

#[test]
fn control_flow() {
    // Method(LOOP) { Store(0, Local0) While(LLess(Local0, 10)) { Increment(Local0) }
    //   If(LEqual(Local0, 10)) { Return(Multiply(Local0, 3, )) } Else { Return(0) } }
    let w = cat(&[&[0xA2], &pkg(&[0x95, 0x60, 0x0A, 0x0A, 0x75, 0x60])]);
    let then = cat(&[&[0xA0], &pkg(&cat(&[&[0x93, 0x60, 0x0A, 0x0A], &[0xA4, 0x77, 0x60, 0x0A, 3, 0x00]]))]);
    let els = cat(&[&[0xA1], &pkg(&[0xA4, 0x00])]);
    let body = cat(&[&[0x14], &pkg(&cat(&[b"LOOP", &[0x00, 0x70, 0x00, 0x60], &w, &then, &els]))]);
    let mut i = load(&body);
    assert_eq!(int(&mut i, "\\LOOP", vec![]), 30);
}

#[test]
fn devices_and_lookup() {
    // Scope(\_SB) { Device(PCI0) { Name(_HID, EisaId("PNP0A08")) Name(_ADR, 0)
    //   Method(_STA) { Return(0x0F) } Method(PATH) { Return(\_SB.PCI0._ADR) } } }
    let hid = crate::exec::eisa_id(b"PNP0A08").unwrap();
    let dev = cat(&[
        &[0x5B, 0x82],
        &pkg(&cat(&[
            b"PCI0",
            &[0x08],
            b"_HID",
            &[0x0C],
            &hid.to_le_bytes(),
            &[0x08],
            b"_ADR",
            &[0x00],
            &[0x14],
            &pkg(&cat(&[b"_STA", &[0x00, 0xA4, 0x0A, 0x0F]])),
            &[0x14],
            &pkg(&cat(&[b"PATH", &[0x00, 0xA4, 0x5C, 0x2F, 3], b"_SB_", b"PCI0", b"_ADR"])),
        ])),
    ]);
    let body = cat(&[&[0x10], &pkg(&cat(&[&[0x5C], b"_SB_", &dev]))]);
    let mut i = load(&body);
    let pci = i.find("\\_SB.PCI0").unwrap();
    assert!(matches!(i.object(pci), Object::Device));
    assert_eq!(i.path(pci), "\\_SB_.PCI0");
    assert_eq!(i.status(pci), 0x0F);
    assert_eq!(int(&mut i, "\\_SB.PCI0._HID", vec![]), u64::from(hid));
    assert_eq!(int(&mut i, "\\_SB.PCI0.PATH", vec![]), 0);
    assert_eq!(i.initialize(), 0);
}

#[test]
fn fields_over_memory() {
    // OperationRegion(GNVS, SystemMemory, 0x1000, 0x10)
    // Field(GNVS, AnyAcc, NoLock, Preserve) { A, 8, B, 4, C, 4, , 8, D, 16 }
    // Method(SETC, 1) { Store(Arg0, C) } Method(GETD) { Return(D) }
    let region = cat(&[&[0x5B, 0x80], b"GNVS", &[0x00, 0x0B, 0x00, 0x10, 0x0A, 0x10]]);
    let field = cat(&[
        &[0x5B, 0x81],
        &pkg(&cat(&[b"GNVS", &[0x00], b"A___", &[8], b"B___", &[4], b"C___", &[4], &[0x00, 8], b"D___", &[16]])),
    ]);
    let setc = cat(&[&[0x14], &pkg(&cat(&[b"SETC", &[0x01, 0x70, 0x68], b"C___"]))]);
    let getd = cat(&[&[0x14], &pkg(&cat(&[b"GETD", &[0x00, 0xA4], b"D___"]))]);
    let mut i = load(&cat(&[&region, &field, &setc, &getd]));
    i.host.bytes.insert(0x1001, 0x5A);
    i.host.bytes.insert(0x1003, 0x34);
    i.host.bytes.insert(0x1004, 0x12);
    assert_eq!(int(&mut i, "\\GETD", vec![]), 0x1234);
    assert_eq!(int(&mut i, "\\B", vec![]), 0xA);
    i.evaluate("\\SETC", vec![Value::Integer(3)]).unwrap();
    // C is the high nibble of 0x1001; B (the low one) is preserved.
    assert_eq!(i.host.bytes[&0x1001], 0x3A);
}

#[test]
fn packages_and_references() {
    // Name(PKG, Package(3) { 1, "two", Buffer(2) { 3, 4 } })
    // Method(FST) { Return(DerefOf(Index(PKG, 0))) } Method(LEN) { Return(SizeOf(PKG)) }
    // Method(BYT) { Return(DerefOf(Index(DerefOf(Index(PKG, 2)), 1))) }
    let p =
        cat(&[&[0x08], b"PKG_", &[0x12], &pkg(&cat(&[&[3, 0x01, 0x0D], b"two\0", &[0x11], &pkg(&[0x0A, 2, 3, 4])]))]);
    let fst = cat(&[&[0x14], &pkg(&cat(&[b"FST_", &[0x00, 0xA4, 0x83, 0x88], b"PKG_", &[0x00, 0x00]]))]);
    let len = cat(&[&[0x14], &pkg(&cat(&[b"LEN_", &[0x00, 0xA4, 0x87], b"PKG_"]))]);
    let byt = cat(&[
        &[0x14],
        &pkg(&cat(&[b"BYT_", &[0x00, 0xA4, 0x83, 0x88, 0x83, 0x88], b"PKG_", &[0x0A, 2, 0x00, 0x01, 0x00]])),
    ]);
    let mut i = load(&cat(&[&p, &fst, &len, &byt]));
    assert_eq!(int(&mut i, "\\FST", vec![]), 1);
    assert_eq!(int(&mut i, "\\LEN", vec![]), 3);
    assert_eq!(int(&mut i, "\\BYT", vec![]), 4);
}

#[test]
fn osi_answers_like_windows() {
    // Method(OSW) { If(_OSI("Windows 2015")) { Return(1) } Return(0) }
    // Method(OSL) { If(_OSI("Linux")) { Return(1) } Return(0) }
    let m = |name: &[u8], s: &[u8]| {
        cat(&[
            &[0x14],
            &pkg(&cat(&[name, &[0x00, 0xA0], &pkg(&cat(&[b"_OSI", &[0x0D], s, &[0, 0xA4, 0x01]])), &[0xA4, 0x00]])),
        ])
    };
    let mut i = load(&cat(&[&m(b"OSW_", b"Windows 2015"), &m(b"OSL_", b"Linux")]));
    assert_eq!(int(&mut i, "\\OSW", vec![]), 1);
    assert_eq!(int(&mut i, "\\OSL", vec![]), 0);
}

#[test]
fn a_bad_term_costs_its_scope() {
    // Device(BAD) { Name(X, 1) <0xF0: no such opcode> } Device(GOOD) { Name(Y, 2) }
    let bad = cat(&[&[0x5B, 0x82], &pkg(&cat(&[b"BAD_", &[0x08], b"X___", &[0x01, 0xF0]]))]);
    let good = cat(&[&[0x5B, 0x82], &pkg(&cat(&[b"GOOD", &[0x08], b"Y___", &[0x0A, 2]]))]);
    let mut i = Interpreter::new(Mem::default());
    i.load(&table(&cat(&[&bad, &good]), 2)).unwrap();
    assert_eq!(i.problems().len(), 1);
    assert_eq!(i.problems()[0].error, Error::BadOpcode(0xF0));
    assert_eq!(int(&mut i, "\\GOOD.Y", vec![]), 2);
    assert_eq!(int(&mut i, "\\BAD_.X", vec![]), 1);
}

#[test]
fn buffer_fields_and_method_objects() {
    // Name(BUF, Buffer(8) {}) CreateDWordField(BUF, 4, DW)
    // Method(SET) { Name(TMP, 0x12345678) Store(TMP, DW) Notify(\BUF, 0x80) }
    let buf = cat(&[&[0x08], b"BUF_", &[0x11], &pkg(&[0x0A, 8])]);
    let dw = cat(&[&[0x8A], b"BUF_", &[0x0A, 4], b"DW__"]);
    let set = cat(&[
        &[0x14],
        &pkg(&cat(&[
            b"SET_",
            &[0x00, 0x08],
            b"TMP_",
            &[0x0C, 0x78, 0x56, 0x34, 0x12],
            &[0x70],
            b"TMP_",
            b"DW__",
            &[0x86, 0x5C],
            b"BUF_",
            &[0x0A, 0x80],
        ])),
    ]);
    let mut i = load(&cat(&[&buf, &dw, &set]));
    i.evaluate("\\SET", vec![]).unwrap();
    let Value::Buffer(b) = i.evaluate("\\BUF", vec![]).unwrap() else { panic!() };
    assert_eq!(&b.borrow()[4..], &[0x78, 0x56, 0x34, 0x12]);
    // The method's TMP went when it returned.
    assert!(i.find("\\SET.TMP").is_none());
    assert_eq!(i.host.notified, vec![("\\BUF_".into(), 0x80)]);
}

#[test]
fn integers_are_32_bit_in_old_tables() {
    // Method(ONES) { Return(Ones) }
    let body = cat(&[&[0x14], &pkg(&cat(&[b"ONES", &[0x00, 0xA4, 0xFF]]))]);
    let mut i = Interpreter::new(Mem::default());
    i.load(&table(&body, 1)).unwrap();
    assert_eq!(int(&mut i, "\\ONES", vec![]), 0xFFFF_FFFF);
}

#[test]
fn forward_names_in_packages() {
    // Name(LNK, Package(1) { LATE }) Device(LATE) {} Method(GET) { Return(DerefOf(Index(LNK, 0))) }
    let lnk = cat(&[&[0x08], b"LNK_", &[0x12], &pkg(&cat(&[&[1], b"LATE"]))]);
    let late = cat(&[&[0x5B, 0x82], &pkg(b"LATE")]);
    let get = cat(&[&[0x14], &pkg(&cat(&[b"GET_", &[0x00, 0xA4, 0x83, 0x88], b"LNK_", &[0x00, 0x00]]))]);
    let mut i = load(&cat(&[&lnk, &late, &get]));
    let late = i.find("\\LATE").unwrap();
    assert!(matches!(i.evaluate("\\GET", vec![]).unwrap(), Value::Node(n) if n == late));
}

#[test]
fn cond_ref_of_a_method_does_not_call_it() {
    // Name(N, 0) Method(INC) { Increment(N) }
    // Method(T) { If(CondRefOf(INC)) { INC } If(CondRefOf(NOPE)) { INC } Return(N) }
    // (the reference PC's GPP7._STA does If(CondRefOf(SSTA)) { SSTA }.)
    let n = cat(&[&[0x08], b"N___", &[0x00]]);
    let inc = cat(&[&[0x14], &pkg(&cat(&[b"INC_", &[0x00, 0x75], b"N___"]))]);
    let t = cat(&[
        &[0x14],
        &pkg(&cat(&[
            b"T___",
            &[0x00, 0xA0],
            &pkg(&cat(&[&[0x5B, 0x12], b"INC_", &[0x00], b"INC_"])),
            &[0xA0],
            &pkg(&cat(&[&[0x5B, 0x12], b"NOPE", &[0x00], b"INC_"])),
            &[0xA4],
            b"N___",
        ])),
    ]);
    let mut i = load(&cat(&[&n, &inc, &t]));
    assert_eq!(int(&mut i, "\\T", vec![]), 1);
}

#[test]
fn events_buttons_and_thermal_zones() {
    use crate::events;
    // Scope(\_GPE) { Method(_L08) { Notify(\_SB.PWRB, 0x80) } Method(_E1A) {}
    //   Method(_L02) {} Method(XYZ) {} }
    let method = |name: &[u8], body: &[u8]| cat(&[&[0x14], &pkg(&cat(&[name, &[0x00], body]))]);
    let notify = cat(&[&[0x86, 0x5C, 0x2E], b"_SB_", b"PWRB", &[0x0A, 0x80]]);
    let gpe = cat(&[
        &[0x10],
        &pkg(&cat(&[
            &[0x5C],
            b"_GPE",
            &method(b"_L08", &notify),
            &method(b"_E1A", &[]),
            &method(b"_L02", &[]),
            &method(b"XYZ_", &[]),
        ])),
    ]);
    // Scope(\_SB) { Device(PWRB) { Name(_HID, EisaId("PNP0C0C")) }
    //   Device(LAN0) { Name(_HID, "ABCD0001") Name(_CID, Package() { EisaId("PNP0C0E") })
    //     Name(_PRW, Package() { 0x02, 4 }) } }
    let eisa = |id: &[u8]| cat(&[&[0x0C], &crate::exec::eisa_id(id).unwrap().to_le_bytes()]);
    let pwrb = cat(&[&[0x5B, 0x82], &pkg(&cat(&[b"PWRB", &[0x08], b"_HID", &eisa(b"PNP0C0C")]))]);
    let lan = cat(&[
        &[0x5B, 0x82],
        &pkg(&cat(&[
            b"LAN0",
            &[0x08],
            b"_HID",
            &[0x0D],
            b"ABCD0001\0",
            &[0x08],
            b"_CID",
            &[0x12],
            &pkg(&cat(&[&[1], &eisa(b"PNP0C0E")])),
            &[0x08],
            b"_PRW",
            &[0x12],
            &pkg(&[2, 0x0A, 0x02, 0x0A, 4]),
        ])),
    ]);
    let sb = cat(&[&[0x10], &pkg(&cat(&[&[0x5C], b"_SB_", &pwrb, &lan]))]);
    // Scope(\_TZ) { ThermalZone(TZ0) { Method(_TMP) { Return(3132) } Name(_CRT, 3732) } }
    let tz0 = cat(&[
        &[0x5B, 0x85],
        &pkg(&cat(&[b"TZ0_", &method(b"_TMP", &[0xA4, 0x0B, 0x3C, 0x0C]), &[0x08], b"_CRT", &[0x0B, 0x94, 0x0E]])),
    ]);
    let tz = cat(&[&[0x10], &pkg(&cat(&[&[0x5C], b"_TZ_", &tz0]))]);
    let mut i = load(&cat(&[&gpe, &sb, &tz]));

    let handlers: Vec<(u8, bool)> = events::gpe_handlers(&i).iter().map(|h| (h.number, h.edge)).collect();
    assert_eq!(handlers, vec![(0x02, false), (0x08, false), (0x1A, true)]);
    assert_eq!(events::wake_gpes(&mut i), vec![0x02]);

    let pwrb = i.find("\\_SB.PWRB").unwrap();
    let lan = i.find("\\_SB.LAN0").unwrap();
    assert_eq!(events::devices_with_id(&mut i, b"PNP0C0C"), vec![pwrb]);
    assert!(events::has_id(&mut i, lan, b"PNP0C0E"));
    assert!(events::has_id(&mut i, lan, b"ABCD0001"));
    assert!(!events::has_id(&mut i, pwrb, b"PNP0C0E"));

    // The level handler notifies the button.
    let l08 = events::gpe_handlers(&i)[1].method;
    i.evaluate_node(l08, vec![]).unwrap();
    assert_eq!(i.host.notified, vec![("\\_SB_.PWRB".into(), 0x80)]);

    let zones = events::thermal_zones(&i);
    assert_eq!(zones, vec![i.find("\\_TZ.TZ0").unwrap()]);
    assert_eq!(events::millicelsius(int(&mut i, "\\_TZ.TZ0._TMP", vec![])), 40_000);
    assert_eq!(events::millicelsius(int(&mut i, "\\_TZ.TZ0._CRT", vec![])), 100_000);
}
