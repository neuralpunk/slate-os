// SPDX-License-Identifier: MIT OR Apache-2.0

//! Arrays and variable attributes (bash): indexed arrays (`a=(x y)`,
//! `a[3]=z`, sparse, negative subscripts from the end), associative ones
//! (`declare -A m; m[key]=v`), and the `-i`, `-l`, `-u` attributes; the
//! text `declare -p` prints for each variable.
//!
//! An array literal's expanded elements travel as one value: a NUL byte,
//! then the elements separated by NULs, a keyed element as `\x01KEY\x02VALUE`
//! (shell values never hold NUL, so nothing real looks like this).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::shell::{Shell, Var, text};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Array {
    #[default]
    None,
    Indexed(BTreeMap<i64, Vec<u8>>),
    Assoc(AssocMap),
}

/// An associative array, kept so that it lists its keys in the order
/// bash does. bash's order was found by observation (bash 5.3, keys
/// listed after known inserts): FNV-1, the public 32-bit hash, picks one
/// of 1024 buckets; buckets list in order, each newest key first; before
/// an insert into a table holding twice as many keys as buckets, the
/// table grows fourfold, moving each bucket's keys in turn to the front
/// of their new buckets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssocMap {
    buckets: Vec<Vec<(Vec<u8>, Vec<u8>)>>,
    len: usize,
}

impl Default for AssocMap {
    fn default() -> Self {
        AssocMap::new()
    }
}

fn fnv1(k: &[u8]) -> u32 {
    k.iter().fold(2_166_136_261u32, |h, &c| h.wrapping_mul(16_777_619) ^ u32::from(c))
}

impl AssocMap {
    pub fn new() -> AssocMap {
        AssocMap { buckets: Vec::new(), len: 0 }
    }

    fn size(&self) -> usize {
        self.buckets.len().max(1024)
    }

    fn bucket(&self, k: &[u8]) -> usize {
        fnv1(k) as usize & (self.size() - 1)
    }

    pub fn get(&self, k: &[u8]) -> Option<&Vec<u8>> {
        let b = self.buckets.get(self.bucket(k))?;
        b.iter().find(|(key, _)| key == k).map(|(_, v)| v)
    }

    pub fn insert(&mut self, k: Vec<u8>, v: Vec<u8>) {
        if self.buckets.is_empty() {
            self.buckets.resize(1024, Vec::new());
        }
        let i = self.bucket(&k);
        if let Some(e) = self.buckets[i].iter_mut().find(|(key, _)| *key == k) {
            e.1 = v;
            return;
        }
        if self.len >= 2 * self.size() {
            let size = self.size() * 4;
            let mut nb: Vec<Vec<(Vec<u8>, Vec<u8>)>> = alloc::vec![Vec::new(); size];
            for chain in core::mem::take(&mut self.buckets) {
                for e in chain {
                    nb[fnv1(&e.0) as usize & (size - 1)].insert(0, e);
                }
            }
            self.buckets = nb;
        }
        let i = self.bucket(&k);
        self.buckets[i].insert(0, (k, v));
        self.len += 1;
    }

    pub fn remove(&mut self, k: &[u8]) -> Option<Vec<u8>> {
        let i = self.bucket(k);
        let b = self.buckets.get_mut(i)?;
        let at = b.iter().position(|(key, _)| key == k)?;
        self.len -= 1;
        Some(b.remove(at).1)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Keys and values in bash's order.
    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &Vec<u8>)> {
        self.buckets.iter().flatten().map(|(k, v)| (k, v))
    }

    pub fn keys(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.iter().map(|(k, _)| k)
    }

    pub fn values(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.iter().map(|(_, v)| v)
    }
}

impl Array {
    pub fn is_some(&self) -> bool {
        !matches!(self, Array::None)
    }

    /// The element `key` names (a number for indexed arrays).
    pub fn get_text(&self, key: &[u8]) -> Option<Vec<u8>> {
        match self {
            Array::None => None,
            Array::Indexed(m) => m.get(&parse_i64(key)?).cloned(),
            Array::Assoc(m) => m.get(key).cloned(),
        }
    }

    pub fn set_text(&mut self, key: &[u8], value: Vec<u8>) {
        match self {
            Array::None => {}
            Array::Indexed(m) => {
                m.insert(parse_i64(key).unwrap_or(0), value);
            }
            Array::Assoc(m) => {
                m.insert(key.to_vec(), value);
            }
        }
    }

    /// The values in order.
    pub fn values(&self) -> Vec<Vec<u8>> {
        match self {
            Array::None => Vec::new(),
            Array::Indexed(m) => m.values().cloned().collect(),
            Array::Assoc(m) => m.values().cloned().collect(),
        }
    }

    /// The keys in order, as text.
    pub fn keys(&self) -> Vec<Vec<u8>> {
        match self {
            Array::None => Vec::new(),
            Array::Indexed(m) => m.keys().map(|k| alloc::format!("{k}").into_bytes()).collect(),
            Array::Assoc(m) => m.keys().cloned().collect(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Array::None => 0,
            Array::Indexed(m) => m.len(),
            Array::Assoc(m) => m.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn parse_i64(b: &[u8]) -> Option<i64> {
    core::str::from_utf8(b).ok()?.trim().parse().ok()
}

/// An expanded array literal's elements, encoded (see the module docs).
pub fn encode(elems: &[(Option<Vec<u8>>, Vec<u8>)]) -> Vec<u8> {
    let mut out = alloc::vec![0u8];
    for (i, (k, v)) in elems.iter().enumerate() {
        if i > 0 {
            out.push(0);
        }
        if let Some(k) = k {
            out.push(1);
            out.extend_from_slice(k);
            out.push(2);
        }
        out.extend_from_slice(v);
    }
    out
}

/// An array literal's elements: an optional `[key]=` and the value.
pub type Elems = Vec<(Option<Vec<u8>>, Vec<u8>)>;

/// The elements of an encoded literal, or None for a plain value.
pub fn decode(v: &[u8]) -> Option<Elems> {
    let rest = v.strip_prefix(&[0])?;
    if rest.is_empty() {
        return Some(Vec::new());
    }
    Some(
        rest.split(|&c| c == 0)
            .map(|e| match e.strip_prefix(&[1]) {
                Some(kv) => {
                    let sep = kv.iter().position(|&c| c == 2).unwrap_or(kv.len());
                    (Some(kv[..sep].to_vec()), kv.get(sep + 1..).unwrap_or_default().to_vec())
                }
                None => (None, e.to_vec()),
            })
            .collect(),
    )
}

/// `declare -p`'s quoting: double quotes, with `"`, `\`, `$` and `` ` ``
/// escaped.
pub fn dquote(v: &[u8]) -> Vec<u8> {
    let mut o = alloc::vec![b'"'];
    for &c in v {
        if matches!(c, b'"' | b'\\' | b'$' | b'`') {
            o.push(b'\\');
        }
        o.push(c);
    }
    o.push(b'"');
    o
}

/// An array subscript key as an assignment or expansion gives it.
#[derive(Debug)]
pub enum Key {
    Index(i64),
    Name(Vec<u8>),
}

impl Shell {
    /// The value an assignment to `name` stores, after its attributes:
    /// arithmetic for `-i` (added to the old value with `append`), case
    /// for `-l`/`-u`.
    pub fn attribute_value(&mut self, name: &[u8], value: &[u8], append: bool) -> Vec<u8> {
        let name = &self.resolve(name)[..];
        let (integer, case) = self.vars.get(name).map_or((false, 0), |v| (v.integer, v.case));
        let mut v = value.to_vec();
        if integer {
            let n = match crate::arith::eval(value, self) {
                Ok(n) => n,
                Err(e) => {
                    crate::error(format_args!("{}: {e}", text(value)));
                    0
                }
            };
            let old = if append { self.get_var(name).and_then(|o| parse_i64(&o)).unwrap_or(0) } else { 0 };
            v = alloc::format!("{}", old.wrapping_add(n)).into_bytes();
        }
        match case {
            b'l' => v.make_ascii_lowercase(),
            b'u' => v.make_ascii_uppercase(),
            _ => {}
        }
        v
    }

    pub fn is_assoc(&self, name: &[u8]) -> bool {
        self.vars.get(&self.resolve(name)).is_some_and(|v| matches!(v.array, Array::Assoc(_)))
    }

    /// The key a subscript names: its text for an associative array, its
    /// arithmetic value for an indexed one (negative: from the end).
    pub fn key_of(&mut self, name: &[u8], sub: &[u8]) -> Option<Key> {
        if self.is_assoc(name) {
            return Some(Key::Name(sub.to_vec()));
        }
        let n = crate::arith::eval(sub, self).map_err(|e| crate::error(format_args!("{}: {e}", text(sub)))).ok()?;
        if n < 0 {
            let top = match self.vars.get(name).map(|v| &v.array) {
                Some(Array::Indexed(m)) => m.keys().next_back().map_or(0, |k| k + 1),
                _ => i64::from(self.vars.get(name).is_some_and(|v| !v.unset)),
            };
            if top + n < 0 {
                crate::error(format_args!("{}: bad array subscript", text(name)));
                return None;
            }
            return Some(Key::Index(top + n));
        }
        Some(Key::Index(n))
    }

    /// The element `sub` of `name` (a scalar is element 0).
    pub fn get_elem(&mut self, name: &[u8], sub: &[u8]) -> Option<Vec<u8>> {
        let name = &self.resolve(name)[..];
        if let Some(a) = self.special_array(name) {
            let i = crate::arith::eval(sub, self).ok()?;
            let i = if i < 0 { a.len() as i64 + i } else { i };
            return a.get(usize::try_from(i).ok()?).cloned();
        }
        let key = self.key_of(name, sub)?;
        let v = self.vars.get(name)?;
        match (&v.array, key) {
            (Array::Indexed(m), Key::Index(i)) => m.get(&i).cloned(),
            (Array::Assoc(m), Key::Name(k)) => m.get(&k).cloned(),
            (Array::None, Key::Index(0)) if !v.unset => Some(v.value.clone()),
            _ => None,
        }
    }

    /// All elements of `name` (`${name[@]}`): a scalar is a one-element
    /// array; an unset name none.
    pub fn elements(&mut self, name: &[u8]) -> Vec<Vec<u8>> {
        let name = &self.resolve(name)[..];
        if let Some(a) = self.special_array(name) {
            return a;
        }
        match self.vars.get(name) {
            Some(v) if v.array.is_some() => v.array.values(),
            Some(v) if !v.unset => alloc::vec![v.value.clone()],
            _ => Vec::new(),
        }
    }

    pub fn element_keys(&mut self, name: &[u8]) -> Vec<Vec<u8>> {
        let name = &self.resolve(name)[..];
        if let Some(a) = self.special_array(name) {
            return (0..a.len()).map(|i| alloc::format!("{i}").into_bytes()).collect();
        }
        match self.vars.get(name) {
            Some(v) if v.array.is_some() => v.array.keys(),
            Some(v) if !v.unset => alloc::vec![b"0".to_vec()],
            _ => Vec::new(),
        }
    }

    /// Set element `sub` of `name` (making it an indexed array if it was
    /// a scalar).
    pub fn set_elem(&mut self, name: &[u8], sub: &[u8], value: &[u8], append: bool) -> bool {
        let name = &self.resolve(name)[..];
        if self.vars.get(name).is_some_and(|v| v.readonly) {
            crate::error(format_args!("{}: readonly variable", text(name)));
            return false;
        }
        let Some(key) = self.key_of(name, sub) else { return false };
        let old = match &key {
            Key::Index(i) => self.get_elem(name, alloc::format!("{i}").as_bytes()),
            Key::Name(k) => self.vars.get(name).and_then(|v| v.array.get_text(k)),
        };
        let mut val = self.attribute_value(name, value, append);
        let integer = self.vars.get(name).is_some_and(|v| v.integer);
        if append && !integer {
            let mut o = old.unwrap_or_default();
            o.extend_from_slice(&val);
            val = o;
        }
        let v = self.vars.entry(name.to_vec()).or_default();
        if !v.array.is_some() {
            let mut m = BTreeMap::new();
            if !v.unset && !v.value.is_empty() {
                m.insert(0, core::mem::take(&mut v.value));
            }
            v.array = Array::Indexed(m);
        }
        v.unset = false;
        match (&mut v.array, key) {
            (Array::Indexed(m), Key::Index(i)) => {
                m.insert(i, val);
            }
            (Array::Assoc(m), Key::Name(k)) => {
                m.insert(k, val);
            }
            _ => return false,
        }
        true
    }

    pub fn unset_elem(&mut self, name: &[u8], sub: &[u8]) -> bool {
        let name = &self.resolve(name)[..];
        let Some(key) = self.key_of(name, sub) else { return false };
        if let Some(v) = self.vars.get_mut(name) {
            match (&mut v.array, key) {
                (Array::Indexed(m), Key::Index(i)) => {
                    m.remove(&i);
                }
                (Array::Assoc(m), Key::Name(k)) => {
                    m.remove(&k);
                }
                (Array::None, Key::Index(0)) => {
                    v.value.clear();
                    v.unset = true;
                }
                _ => {}
            }
        }
        true
    }

    /// `name=(...)` or `name+=(...)`: the elements, keyed or in order.
    pub fn assign_array(&mut self, name: &[u8], elems: Elems, append: bool) -> bool {
        let name = &self.resolve(name)[..];
        if self.vars.get(name).is_some_and(|v| v.readonly) {
            crate::error(format_args!("{}: readonly variable", text(name)));
            return false;
        }
        let assoc = self.is_assoc(name);
        {
            let v = self.vars.entry(name.to_vec()).or_default();
            if !append || !v.array.is_some() {
                let keep = append && !v.unset && !v.value.is_empty() && !assoc;
                let mut m = BTreeMap::new();
                if keep {
                    m.insert(0, core::mem::take(&mut v.value));
                }
                v.array = if assoc { Array::Assoc(AssocMap::new()) } else { Array::Indexed(m) };
            }
            v.unset = false;
        }
        let mut next = match self.vars.get(name).map(|v| &v.array) {
            Some(Array::Indexed(m)) => m.keys().next_back().map_or(0, |k| k + 1),
            _ => 0,
        };
        for (k, value) in elems {
            let value = self.attribute_value(name, &value, false);
            if assoc {
                let Some(k) = k else {
                    crate::error(format_args!(
                        "{}: {}: must use subscript when assigning associative array",
                        text(name),
                        text(&value)
                    ));
                    continue;
                };
                if let Some(Array::Assoc(m)) = self.vars.get_mut(name).map(|v| &mut v.array) {
                    m.insert(k, value);
                }
                continue;
            }
            let i = match k {
                Some(k) => match crate::arith::eval(&k, self) {
                    Ok(i) => i,
                    Err(e) => {
                        crate::error(format_args!("{}: {e}", text(&k)));
                        continue;
                    }
                },
                None => next,
            };
            if let Some(Array::Indexed(m)) = self.vars.get_mut(name).map(|v| &mut v.array) {
                m.insert(i, value);
            }
            next = i + 1;
        }
        true
    }

    /// An assignment written as text, as declaration built-ins and
    /// `read`-like built-ins get it: `name=value`, `name+=value`,
    /// `name[sub]=value`, or `name=` with an encoded array literal.
    /// Returns the name, or None if it is not a valid assignment.
    pub fn assign_text(&mut self, arg: &[u8]) -> Option<(Vec<u8>, bool)> {
        let eq = arg.iter().position(|&c| c == b'=')?;
        self.assign_parts(&arg[..eq], &arg[eq + 1..])
    }

    /// An assignment from its left side (`name`, `name+`, `name[sub]`,
    /// `name[sub]+`) and value: whether it took.
    pub fn assign_lhs(&mut self, lhs: &[u8], value: &[u8]) -> bool {
        self.assign_parts(lhs, value).is_some_and(|(_, ok)| ok)
    }

    fn assign_parts(&mut self, lhs: &[u8], value: &[u8]) -> Option<(Vec<u8>, bool)> {
        let mut lhs = lhs;
        let append = lhs.ends_with(b"+");
        if append {
            lhs = &lhs[..lhs.len() - 1];
        }
        let (name, sub) = match lhs.iter().position(|&c| c == b'[') {
            Some(b) if lhs.ends_with(b"]") => (&lhs[..b], Some(&lhs[b + 1..lhs.len() - 1])),
            _ => (lhs, None),
        };
        if !crate::parser::is_name(name) {
            return None;
        }
        // Through a name reference to an element: that element.
        let target = self.resolve(name);
        if sub.is_none()
            && let Some((n, s)) = crate::shell::split_subscript(&target)
        {
            let (n, s) = (n.to_vec(), s.to_vec());
            return Some((name.to_vec(), self.set_elem(&n, &s, value, append)));
        }
        let name = if self.is_nameref(name) { &target[..] } else { name };
        let ok = match (sub, decode(value)) {
            (None, Some(elems)) => self.assign_array(name, elems, append),
            (Some(s), _) => self.set_elem(name, s, value, append),
            (None, None) if append => {
                let integer = self.vars.get(name).is_some_and(|v| v.integer);
                if integer {
                    let v = self.attribute_value(name, value, true);
                    self.set_raw(name, v)
                } else {
                    let mut old = self.get_var(name).unwrap_or_default();
                    old.extend_from_slice(value);
                    self.set_var(name, &old)
                }
            }
            (None, None) => self.set_var(name, value),
        };
        Some((name.to_vec(), ok))
    }

    /// Set `name`'s scalar value as given (attributes already applied).
    fn set_raw(&mut self, name: &[u8], value: Vec<u8>) -> bool {
        if self.vars.get(name).is_some_and(|v| v.readonly) {
            crate::error(format_args!("{}: readonly variable", text(name)));
            return false;
        }
        let v = self.vars.entry(name.to_vec()).or_default();
        if v.array.is_some() {
            v.array.set_text(b"0", value);
        } else {
            v.value = value;
            v.unset = false;
        }
        true
    }

    /// `declare -p name`'s line.
    pub fn declaration(&self, name: &[u8], v: &Var) -> Vec<u8> {
        let mut flags = String::new();
        if matches!(v.array, Array::Indexed(_)) {
            flags.push('a');
        }
        if matches!(v.array, Array::Assoc(_)) {
            flags.push('A');
        }
        if v.integer {
            flags.push('i');
        }
        if v.readonly {
            flags.push('r');
        }
        match v.case {
            b'l' => flags.push('l'),
            b'u' => flags.push('u'),
            _ => {}
        }
        if v.exported {
            flags.push('x');
        }
        if flags.is_empty() {
            flags.push('-');
        }
        if v.nameref {
            flags = String::from("n");
            if v.readonly {
                flags.push('r');
            }
            if v.exported {
                flags.push('x');
            }
        }
        let mut out = alloc::format!("declare -{flags} ").into_bytes();
        out.extend_from_slice(name);
        match &v.array {
            // Declared, never assigned: `declare -a e`.
            _ if v.unset => {}
            Array::Indexed(m) => {
                out.extend_from_slice(b"=(");
                for (i, (k, val)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(b' ');
                    }
                    out.extend_from_slice(alloc::format!("[{k}]=").as_bytes());
                    out.extend(dquote(val));
                }
                out.push(b')');
            }
            Array::Assoc(m) => {
                out.extend_from_slice(b"=(");
                for (k, val) in m.iter() {
                    out.push(b'[');
                    out.extend_from_slice(k);
                    out.extend_from_slice(b"]=");
                    out.extend(dquote(val));
                    out.push(b' ');
                }
                out.push(b')');
            }
            Array::None => {
                out.push(b'=');
                out.extend(dquote(&v.value));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_encoding() {
        let e = alloc::vec![(None, b"a".to_vec()), (Some(b"3".to_vec()), b"b c".to_vec()), (None, Vec::new())];
        assert_eq!(decode(&encode(&e)), Some(e));
        assert_eq!(decode(&encode(&[])), Some(Vec::new()));
        assert_eq!(decode(b"plain"), None);
    }

    #[test]
    fn indexed_and_assoc() {
        let mut sh = Shell::new();
        sh.assign_text(
            &[
                b"a=".as_slice(),
                &encode(&[(None, b"x".to_vec()), (None, b"y".to_vec()), (Some(b"5".to_vec()), b"z".to_vec())]),
            ]
            .concat(),
        );
        assert_eq!(sh.elements(b"a"), [b"x".to_vec(), b"y".to_vec(), b"z".to_vec()]);
        assert_eq!(sh.element_keys(b"a"), [b"0".to_vec(), b"1".to_vec(), b"5".to_vec()]);
        assert_eq!(sh.get_elem(b"a", b"-1"), Some(b"z".to_vec()));
        assert_eq!(sh.get_var(b"a"), Some(b"x".to_vec()));
        sh.assign_text(b"a[1]+=Y");
        assert_eq!(sh.get_elem(b"a", b"1"), Some(b"yY".to_vec()));
        sh.unset_elem(b"a", b"0");
        assert_eq!(sh.get_var(b"a"), None);
        let decl = sh.declaration(b"a", &sh.vars.get(b"a".as_slice()).unwrap().clone());
        assert_eq!(decl, b"declare -a a=([1]=\"yY\" [5]=\"z\")");
        sh.vars.insert(b"m".to_vec(), Var { array: Array::Assoc(AssocMap::new()), ..Default::default() });
        sh.assign_text(b"m[k ey]=v$");
        let decl = sh.declaration(b"m", &sh.vars.get(b"m".as_slice()).unwrap().clone());
        assert_eq!(decl, b"declare -A m=([k ey]=\"v\\$\" )");
    }

    #[test]
    fn bash_order() {
        // Orders bash 5.3 printed for these inserts.
        let mut m = AssocMap::new();
        for k in ["one", "two", "three", "four", "five", "alpha", "beta"] {
            m.insert(k.as_bytes().to_vec(), Vec::new());
        }
        let keys: Vec<&[u8]> = m.keys().map(|k| k.as_slice()).collect();
        assert_eq!(keys, [&b"four"[..], b"alpha", b"two", b"three", b"one", b"five", b"beta"]);
        // k8 and k116 share a bucket: the newer first.
        let mut c = AssocMap::new();
        c.insert(b"k8".to_vec(), Vec::new());
        c.insert(b"k116".to_vec(), Vec::new());
        assert_eq!(c.keys().next().map(|k| k.as_slice()), Some(&b"k116"[..]));
        // 2049 keys: the table has grown to 4096 buckets.
        let mut g = AssocMap::new();
        for i in 1..=2049 {
            g.insert(alloc::format!("key{i}").into_bytes(), Vec::new());
        }
        assert_eq!(g.len(), 2049);
        assert_eq!(g.buckets.len(), 4096);
        assert!(g.get(b"key77").is_some());
        assert_eq!(g.remove(b"key77"), Some(Vec::new()));
        assert!(g.get(b"key77").is_none());
    }

    #[test]
    fn attributes() {
        let mut sh = Shell::new();
        sh.vars.insert(b"n".to_vec(), Var { integer: true, ..Default::default() });
        sh.set_var(b"n", b"3*4");
        sh.assign_text(b"n+=2");
        assert_eq!(sh.get_var(b"n"), Some(b"14".to_vec()));
        sh.vars.insert(b"u".to_vec(), Var { case: b'u', ..Default::default() });
        sh.set_var(b"u", b"abc");
        assert_eq!(sh.get_var(b"u"), Some(b"ABC".to_vec()));
    }
}
