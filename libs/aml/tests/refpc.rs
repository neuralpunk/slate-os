// SPDX-License-Identifier: MIT OR Apache-2.0

//! The reference PC's ACPI tables (ADR 0076, ADR 0079): the DSDT and the SSDTs in
//! the firmware's order, loaded, initialized and asked for what the kernel
//! needs. The tables are the vendor's firmware: they are copied from
//! the reference PC into `target/refpc/acpi` and never committed, and the test says
//! so and passes when they are not there.

use std::path::PathBuf;

use slate_aml::{Address, Error, Host, Interpreter, Object, Value};

/// Every read gives zero, writes go nowhere: enough to load and walk.
struct Quiet;

impl Host for Quiet {
    fn read(&mut self, _at: Address, _width: u8) -> Result<u64, Error> {
        Ok(0)
    }
    fn write(&mut self, _at: Address, _width: u8, _value: u64) -> Result<(), Error> {
        Ok(())
    }
}

fn tables() -> Option<Vec<(String, Vec<u8>)>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/refpc/acpi");
    let dsdt = std::fs::read(dir.join("DSDT")).ok()?;
    let mut out = vec![("DSDT".to_string(), dsdt)];
    for n in 1.. {
        let name = format!("SSDT{n}");
        match std::fs::read(dir.join(&name)) {
            Ok(b) => out.push((name, b)),
            Err(_) => break,
        }
    }
    Some(out)
}

fn loaded() -> Option<Interpreter<Quiet>> {
    let tables = tables()?;
    let mut i = Interpreter::new(Quiet);
    for (name, t) in &tables {
        i.load(t).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
    Some(i)
}

#[test]
fn refpc_tables_load_cleanly() {
    let Some(i) = loaded() else {
        eprintln!("the reference PC's tables are not in target/refpc/acpi; skipped");
        return;
    };
    for p in i.problems() {
        eprintln!("table {} at {:#x} in {}: {:?}", p.table, p.offset, p.scope, p.error);
    }
    eprintln!("{} objects", i.len());
    assert!(i.problems().is_empty(), "{} problems", i.problems().len());
    assert!(i.len() > 1000);
}

#[test]
fn refpc_answers_what_the_kernel_asks() {
    let Some(mut i) = loaded() else { return };
    // \_S5: SLP_TYPa 5 on this board (as the old pattern match found).
    let s5 = i.evaluate("\\_S5", vec![]).unwrap();
    let Value::Package(p) = s5 else { panic!("_S5 is not a package") };
    assert_eq!(p.borrow()[0].as_int(), Some(5));
    // The PCI host bridge and its routing table.
    let pci = i.find("\\_SB.PCI0").expect("\\_SB.PCI0");
    assert!(matches!(i.object(pci), Object::Device));
    let prt = i.evaluate("\\_SB.PCI0._PRT", vec![]).expect("_PRT");
    let Value::Package(p) = prt else { panic!("_PRT is not a package") };
    assert!(!p.borrow().is_empty());
    let ran = i.initialize();
    eprintln!("{ran} _INI methods ran; {} entries in _PRT", p.borrow().len());
}

/// Every device's identification and resources, evaluated: what fails, by
/// kind. (`_CRS`, `_PRS`, `_PRT`, `_STA`, `_HID`, `_CID`, `_UID`, `_ADR`.)
#[test]
fn refpc_every_device_evaluates() {
    let Some(mut i) = loaded() else { return };
    i.initialize();
    let mut todo = vec![slate_aml::ROOT];
    let mut devices = Vec::new();
    while let Some(n) = todo.pop() {
        for c in i.children(n) {
            if matches!(i.object(c), Object::Device | Object::Processor { .. } | Object::ThermalZone) {
                devices.push(c);
            }
            todo.push(c);
        }
    }
    let (mut ok, mut failed) = (0, std::collections::BTreeMap::<String, Vec<String>>::new());
    for d in &devices {
        for m in ["_STA", "_HID", "_CID", "_UID", "_ADR", "_CRS", "_PRS", "_PRT"] {
            match i.evaluate_child(*d, m, vec![]) {
                Ok(Some(_)) => ok += 1,
                Ok(None) => {}
                Err(e) => {
                    let at: Vec<String> = i.trace().iter().map(|(p, o)| format!("{p}+{o:#x}")).collect();
                    failed.entry(format!("{e:?}")).or_default().push(format!(
                        "{}.{m} [{}]",
                        i.path(*d),
                        at.join(" < ")
                    ));
                }
            }
        }
    }
    eprintln!("{} devices; {ok} evaluations worked", devices.len());
    for (e, at) in &failed {
        eprintln!("{} x {e}: {}", at.len(), at.iter().take(4).cloned().collect::<Vec<_>>().join(", "));
    }
    assert!(failed.is_empty());
}

/// `AML_DUMP=\_SB.PCI0.GPP7._STA cargo test -p slate-aml --test the reference PC dump`
/// prints a method's bytes (a debugging aid).
#[test]
fn dump() {
    let (Some(i), Ok(path)) = (loaded(), std::env::var("AML_DUMP")) else { return };
    let id = i.find(&path).expect("no such object");
    let b = i.method_body(id).expect("not a method");
    for (n, chunk) in b.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|x| format!("{x:02x}")).collect();
        let txt: String = chunk.iter().map(|&x| if x.is_ascii_graphic() { x as char } else { '.' }).collect();
        eprintln!("{:04x}  {:<48} {txt}", n * 16, hex.join(" "));
    }
}

/// `AML_KINDS=SCOPE:NAME,NAME... cargo test -p slate-aml --test the reference PC kinds`
/// prints what each name resolves to from a scope (a debugging aid).
#[test]
fn kinds() {
    let (Some(i), Ok(spec)) = (loaded(), std::env::var("AML_KINDS")) else { return };
    let (scope, names) = spec.split_once(':').unwrap();
    let mut at = i.find(scope).expect("no such scope");
    for n in names.split(',') {
        // Search up the scopes as AML does for single segments.
        let mut found = None;
        loop {
            if let Some(c) = i.child(at, n) {
                found = Some(c);
                break;
            }
            if at == slate_aml::ROOT {
                break;
            }
            at = i.find(&i.path(at).rsplit_once('.').map(|x| x.0.to_string()).unwrap_or("\\".into())).unwrap();
        }
        at = i.find(scope).unwrap();
        match found {
            Some(c) => eprintln!("{n}: {} {:?}", i.path(c), i.object(c)),
            None => eprintln!("{n}: not found"),
        }
    }
}

/// What the kernel's event thread finds on the reference PC (ADR 0079): the
/// general-purpose event handlers, the wake events among them, the power
/// button device and the thermal zones, whose `_TMP` must evaluate.
#[test]
fn refpc_events() {
    use slate_aml::events;
    let Some(mut i) = loaded() else { return };
    i.initialize();
    let handlers = events::gpe_handlers(&i);
    let wake = events::wake_gpes(&mut i);
    let names: Vec<String> = handlers.iter().map(|h| i.path(h.method)).collect();
    eprintln!("handlers {names:?}; wake events {wake:02x?}");
    assert!(handlers.len() >= 9, "{} handlers", handlers.len());
    assert!(!events::devices_with_id(&mut i, b"PNP0C0C").is_empty(), "no power button device");
    let zones = events::thermal_zones(&i);
    assert!(!zones.is_empty());
    for z in zones {
        let path = i.path(z);
        let tmp = i.evaluate_child(z, "_TMP", vec![]).unwrap_or_else(|e| panic!("{path}._TMP: {e:?}"));
        let crt = i.evaluate_child(z, "_CRT", vec![]).ok().flatten().and_then(|v| v.as_int());
        eprintln!("{path}: _TMP {:?}, _CRT {crt:?}", tmp.and_then(|v| v.as_int()));
    }
}
