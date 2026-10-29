// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dependency resolution: which packages to install, in which order
//! (dependencies first), choosing the newest version that satisfies every
//! requirement.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use crate::Error;
use crate::manifest::{Dep, Manifest};
use crate::version::{Op, compare};

/// Plan installing `wanted`. Installed packages that satisfy a requirement
/// stay unless they are named in `upgrade`.
pub fn plan(
    available: &[Manifest],
    installed: &BTreeMap<String, Manifest>,
    wanted: &[Dep],
    upgrade: &BTreeSet<String>,
) -> Result<Vec<Manifest>, Error> {
    let mut chosen: BTreeMap<String, Manifest> = BTreeMap::new();
    let mut order = Vec::new();
    for d in wanted {
        visit(d, available, installed, upgrade, &mut chosen, &mut order)?;
    }
    Ok(order)
}

fn visit(
    dep: &Dep,
    available: &[Manifest],
    installed: &BTreeMap<String, Manifest>,
    upgrade: &BTreeSet<String>,
    chosen: &mut BTreeMap<String, Manifest>,
    order: &mut Vec<Manifest>,
) -> Result<(), Error> {
    if let Some(c) = chosen.get(&dep.name) {
        return if dep.allows(&c.version) { Ok(()) } else { Err(Error::Conflict(dep.clone(), c.version.clone())) };
    }
    if let Some(i) = installed.get(&dep.name)
        && dep.allows(&i.version)
        && !upgrade.contains(&dep.name)
    {
        return Ok(());
    }
    let best = available
        .iter()
        .filter(|m| m.name == dep.name && dep.allows(&m.version))
        .max_by(|a, b| compare(&a.version, &b.version))
        .ok_or_else(|| Error::Missing(dep.clone()))?;
    // An upgrade never goes backwards.
    if let Some(i) = installed.get(&dep.name)
        && compare(&best.version, &i.version).is_le()
    {
        return Ok(());
    }
    chosen.insert(dep.name.clone(), best.clone());
    for d in &best.depends {
        visit(d, available, installed, upgrade, chosen, order)?;
    }
    order.push(best.clone());
    Ok(())
}

/// Installed packages that depend on `name`.
pub fn dependents(installed: &BTreeMap<String, Manifest>, name: &str) -> Vec<String> {
    installed.values().filter(|m| m.depends.iter().any(|d| d.name == name)).map(|m| m.name.clone()).collect()
}

/// A requirement on any version of `name`.
pub fn any(name: &str) -> Dep {
    Dep { name: name.into(), op: Op::Any, version: String::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Abi;

    fn pkg(name: &str, version: &str, deps: &[&str]) -> Manifest {
        let mut m = Manifest::new(name, version);
        m.abi = Abi::Any;
        m.depends = deps.iter().map(|d| Dep::parse(d).unwrap()).collect();
        m
    }

    #[test]
    fn dependencies_first_newest_version() {
        let avail = [
            pkg("app", "1.0", &["lib (>= 2)", "data"]),
            pkg("lib", "1.5", &[]),
            pkg("lib", "2.1", &["data"]),
            pkg("lib", "2.0", &[]),
            pkg("data", "1", &[]),
        ];
        let p = plan(&avail, &BTreeMap::new(), &[any("app")], &BTreeSet::new()).unwrap();
        let ids: Vec<String> = p.iter().map(Manifest::id).collect();
        assert_eq!(ids, ["data-1", "lib-2.1", "app-1.0"]);
    }

    #[test]
    fn installed_and_upgrades() {
        let avail = [pkg("app", "1.1", &["lib"]), pkg("app", "1.0", &["lib"]), pkg("lib", "1", &[])];
        let mut installed = BTreeMap::new();
        installed.insert("app".into(), pkg("app", "1.0", &["lib"]));
        installed.insert("lib".into(), pkg("lib", "1", &[]));
        assert!(plan(&avail, &installed, &[any("app")], &BTreeSet::new()).unwrap().is_empty());
        let up: BTreeSet<String> = ["app".into()].into();
        let p = plan(&avail, &installed, &[any("app")], &up).unwrap();
        assert_eq!(p.iter().map(Manifest::id).collect::<Vec<_>>(), ["app-1.1"]);
        assert_eq!(dependents(&installed, "lib"), ["app"]);
    }

    #[test]
    fn errors() {
        let avail = [pkg("a", "1", &["b (>= 2)"]), pkg("b", "1", &[]), pkg("c", "1", &["b (<< 1)"])];
        assert!(matches!(plan(&avail, &BTreeMap::new(), &[any("a")], &BTreeSet::new()), Err(Error::Missing(_))));
        assert!(matches!(plan(&avail, &BTreeMap::new(), &[any("zzz")], &BTreeSet::new()), Err(Error::Missing(_))));
        // Cycles resolve.
        let cyc = [pkg("x", "1", &["y"]), pkg("y", "1", &["x"])];
        assert_eq!(plan(&cyc, &BTreeMap::new(), &[any("x")], &BTreeSet::new()).unwrap().len(), 2);
    }
}
