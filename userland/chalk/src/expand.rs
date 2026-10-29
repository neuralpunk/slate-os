// SPDX-License-Identifier: MIT OR Apache-2.0

//! Word expansion (POSIX.1-2017 XCU §2.6): brace expansion (bash), tilde,
//! parameter expansion, command substitution, arithmetic, field
//! splitting, pathname expansion and quote removal.
//!
//! While expanding, every byte carries where it came from: quoted
//! (literal), unquoted source text (globbed, not split) or an unquoted
//! expansion result (split on IFS and globbed).

use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::*;
use crate::glob;
use crate::shell::{Flow, Shell, text};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Q {
    Quoted,
    Lit,
    Exp,
}

/// Expansion failed: `${x?msg}`, a bad substitution, `set -u`...
#[derive(Clone, Debug, PartialEq)]
pub enum ExpandError {
    /// Already reported; non-interactive shells exit.
    Fatal,
    Flow(Flow),
}

pub type ExResult<T> = core::result::Result<T, ExpandError>;

/// A field being built: bytes with their origin, and where empty quoted
/// strings stood (`""`, an empty `"$x"`): a field that takes in one of
/// those positions exists even when it is empty.
type Field = (Vec<(u8, Q)>, Vec<usize>);

#[derive(Default)]
struct Acc {
    fields: Vec<Field>,
    cur: Vec<(u8, Q)>,
    marks: Vec<usize>,
}

impl Acc {
    fn push(&mut self, b: &[u8], q: Q) {
        if q == Q::Quoted && b.is_empty() {
            self.mark_exists();
        }
        self.cur.extend(b.iter().map(|&c| (c, q)));
    }
    /// An empty quoted string here.
    fn mark_exists(&mut self) {
        self.marks.push(self.cur.len());
    }
    fn break_field(&mut self) {
        let f = core::mem::take(&mut self.cur);
        self.fields.push((f, core::mem::take(&mut self.marks)));
    }
    fn finish(mut self) -> Vec<Field> {
        self.break_field();
        self.fields
    }
}

/// `"$@"`, `"${a[@]}"` and `"${!a[@]}"`: double quotes around one of these
/// alone make no field when the list is empty.
fn is_list(p: &WordPart) -> bool {
    match p {
        WordPart::Param(p) => {
            (p.name == b"@" && p.op == ParamOp::Get && !p.indirect)
                || p.index.as_ref().is_some_and(|i| word_text(i) == b"@")
        }
        _ => false,
    }
}

/// The literal text of a word (for here-doc delimiters, function names).
pub fn word_text(w: &Word) -> Vec<u8> {
    let mut v = Vec::new();
    for p in w {
        match p {
            WordPart::Lit(b) | WordPart::Quoted(b) => v.extend_from_slice(b),
            WordPart::Escaped(c) => v.push(*c),
            WordPart::DQuote(inner) => v.extend(word_text(inner)),
            WordPart::Param(p) => {
                v.push(b'$');
                v.extend_from_slice(&p.name);
            }
            _ => {}
        }
    }
    v
}

/// Brace expansion (bash): `a{b,c}d` and `{1..5}` / `{a..e}` inside an
/// unquoted literal part.
pub fn braces(w: &Word) -> Vec<Word> {
    for (i, part) in w.iter().enumerate() {
        let WordPart::Lit(lit) = part else { continue };
        let Some((open, close, alts)) = find_brace(lit) else { continue };
        let mut out = Vec::new();
        for alt in alts {
            let mut nw: Word = w[..i].to_vec();
            let mut l = lit[..open].to_vec();
            l.extend_from_slice(&alt);
            l.extend_from_slice(&lit[close + 1..]);
            nw.push(WordPart::Lit(l));
            nw.extend(w[i + 1..].iter().cloned());
            out.extend(braces(&nw));
        }
        return out;
    }
    alloc::vec![w.clone()]
}

/// The first brace group with alternatives in `s`: (open, close, alternatives).
fn find_brace(s: &[u8]) -> Option<(usize, usize, Vec<Vec<u8>>)> {
    let mut start = 0;
    while let Some(o) = s[start..].iter().position(|&c| c == b'{').map(|p| p + start) {
        // `${` is not a brace group.
        if o > 0 && s[o - 1] == b'$' {
            start = o + 1;
            continue;
        }
        let mut depth = 0;
        let mut commas = Vec::new();
        let mut close = None;
        for (k, &c) in s.iter().enumerate().skip(o) {
            match c {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(k);
                        break;
                    }
                }
                b',' if depth == 1 => commas.push(k),
                _ => {}
            }
        }
        let c = close?;
        let inner = &s[o + 1..c];
        if !commas.is_empty() {
            let mut alts = Vec::new();
            let mut prev = o + 1;
            for &k in &commas {
                alts.push(s[prev..k].to_vec());
                prev = k + 1;
            }
            alts.push(s[prev..c].to_vec());
            return Some((o, c, alts));
        }
        if let Some(r) = sequence(inner) {
            return Some((o, c, r));
        }
        start = o + 1;
    }
    None
}

/// `{a..b[..step]}` for integers and single letters.
fn sequence(inner: &[u8]) -> Option<Vec<Vec<u8>>> {
    let s = core::str::from_utf8(inner).ok()?;
    let parts: Vec<&str> = s.split("..").collect();
    if parts.len() < 2 || parts.len() > 3 {
        return None;
    }
    let step: i64 = parts.get(2).map_or(Some(1i64), |x| x.parse().ok())?.abs().max(1);
    if let (Ok(a), Ok(b)) = (parts[0].parse::<i64>(), parts[1].parse::<i64>()) {
        let width =
            if (parts[0].starts_with('0') && parts[0].len() > 1) || (parts[1].starts_with('0') && parts[1].len() > 1) {
                parts[0].len().max(parts[1].len())
            } else {
                0
            };
        let mut v = Vec::new();
        let mut x = a;
        while (a <= b && x <= b) || (a > b && x >= b) {
            v.push(alloc::format!("{x:0width$}").into_bytes());
            x += if a <= b { step } else { -step };
            if v.len() > 100_000 {
                break;
            }
        }
        return Some(v);
    }
    let (a, b) = (parts[0].as_bytes(), parts[1].as_bytes());
    if a.len() == 1 && b.len() == 1 && a[0].is_ascii_alphabetic() && b[0].is_ascii_alphabetic() {
        let (a, b) = (a[0], b[0]);
        let mut v = Vec::new();
        let mut x = a as i64;
        while (a <= b && x <= b as i64) || (a > b && x >= b as i64) {
            v.push(alloc::vec![x as u8]);
            x += if a <= b { step } else { -step };
        }
        return Some(v);
    }
    None
}

impl Shell {
    /// Expand a word into fields (splitting and globbing).
    pub fn expand_fields(&mut self, w: &Word) -> ExResult<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for w in braces(w) {
            let fields = self.expand_raw(&w, true)?;
            for (f, exists) in self.split(fields) {
                if f.is_empty() && !exists {
                    continue;
                }
                let pat: Vec<(u8, bool)> = f.iter().map(|&(c, q)| (c, q == Q::Quoted)).collect();
                if !self.opts.noglob && glob::has_magic(&pat) {
                    let found = glob::expand_with(&pat, self.glob_opts());
                    if !found.is_empty() {
                        out.extend(found);
                        continue;
                    }
                    if self.shopt("failglob") {
                        let pat: Vec<u8> = f.iter().map(|x| x.0).collect();
                        crate::error(format_args!("no match: {}", text(&pat)));
                        return Err(ExpandError::Fatal);
                    }
                    if self.shopt("nullglob") {
                        continue;
                    }
                }
                out.push(f.iter().map(|x| x.0).collect());
            }
        }
        Ok(out)
    }

    /// Pathname expansion's options from `shopt`.
    pub fn glob_opts(&self) -> glob::GlobOpts {
        glob::GlobOpts {
            flags: glob::Flags { ext: self.shopt("extglob"), nocase: self.shopt("nocaseglob") },
            dotglob: self.shopt("dotglob"),
            globstar: self.shopt("globstar"),
        }
    }

    /// Expand words into fields.
    pub fn expand_words(&mut self, ws: &[Word]) -> ExResult<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for w in ws {
            out.extend(self.expand_fields(w)?);
        }
        Ok(out)
    }

    /// Expand without splitting or globbing (assignments, `case` words,
    /// here-documents): one string.
    pub fn expand_single(&mut self, w: &Word) -> ExResult<Vec<u8>> {
        let fields = self.expand_raw(w, false)?;
        let mut v = Vec::new();
        for (i, (f, _)) in fields.iter().enumerate() {
            if i > 0 {
                v.push(b' ');
            }
            v.extend(f.iter().map(|x| x.0));
        }
        Ok(v)
    }

    /// A word as a pattern (case, `${x#pat}`, `[[ == ]]`): quoted bytes
    /// are literal.
    pub fn expand_pattern(&mut self, w: &Word) -> ExResult<Vec<(u8, bool)>> {
        let fields = self.expand_raw(w, false)?;
        let mut v = Vec::new();
        for (i, (f, _)) in fields.iter().enumerate() {
            if i > 0 {
                v.push((b' ', false));
            }
            v.extend(f.iter().map(|&(c, q)| (c, q == Q::Quoted)));
        }
        Ok(v)
    }

    /// A redirection target: like a field expansion that must yield one word.
    pub fn expand_target(&mut self, w: &Word) -> ExResult<Vec<u8>> {
        let mut f = self.expand_fields(w)?;
        if f.len() != 1 {
            crate::error(format_args!("{}: ambiguous redirect", text(&word_text(w))));
            return Err(ExpandError::Fatal);
        }
        Ok(f.pop().unwrap())
    }

    /// Field splitting (§2.6.5): only bytes from unquoted expansions
    /// split; IFS white space around a delimiter counts once, and leading
    /// or trailing IFS white space makes no field.
    /// Fields and whether each exists even when empty.
    fn split(&mut self, fields: Vec<Field>) -> Vec<(Vec<(u8, Q)>, bool)> {
        let ifs = self.get_var(b"IFS").unwrap_or_else(|| b" \t\n".to_vec());
        let delim = |x: &(u8, Q)| x.1 == Q::Exp && ifs.contains(&x.0);
        let white = |x: &(u8, Q)| delim(x) && matches!(x.0, b' ' | b'\t' | b'\n');
        let mut out = Vec::new();
        for (f, marks) in fields {
            if !f.iter().any(delim) {
                let exists = !f.is_empty() || !marks.is_empty();
                out.push((f, exists));
                continue;
            }
            // An empty quoted string inside a run of delimiters makes an
            // empty field of its own there (`$x""$y`).
            let marked = |i: usize| marks.contains(&i);
            let n = f.len();
            let mut i = 0;
            while i < n && white(&f[i]) && !marked(i) {
                i += 1;
            }
            let mut cur = Vec::new();
            let mut cur_exists = false;
            while i < n {
                if !delim(&f[i]) {
                    cur.push(f[i]);
                    cur_exists = true;
                    i += 1;
                    continue;
                }
                out.push((core::mem::take(&mut cur), true));
                cur_exists = false;
                let start = i;
                let stop = |i: usize| i > start && marked(i);
                while i < n && white(&f[i]) && !stop(i) {
                    i += 1;
                }
                if i < n && delim(&f[i]) && !white(&f[i]) && !stop(i) {
                    i += 1;
                    while i < n && white(&f[i]) && !stop(i) {
                        i += 1;
                    }
                }
            }
            if cur_exists || marked(n) {
                out.push((cur, true));
            }
        }
        out
    }

    /// The raw expansion of a word into fields (before splitting).
    fn expand_raw(&mut self, w: &Word, fields_mode: bool) -> ExResult<Vec<Field>> {
        let mut acc = Acc::default();
        let mut first = true;
        for (i, part) in w.iter().enumerate() {
            match part {
                WordPart::Lit(l) if first && l.first() == Some(&b'~') => {
                    let end = l.iter().position(|&c| c == b'/').unwrap_or(l.len());
                    let user = &l[1..end];
                    // `~` alone takes the rest of the word only if nothing
                    // quoted follows in this part.
                    let only = end == l.len() && i + 1 < w.len();
                    let home = if user.is_empty() { self.get_var(b"HOME") } else { Shell::home_of(user) };
                    match home {
                        Some(h) if !only || user.is_empty() => {
                            acc.push(&h, Q::Quoted);
                            acc.push(&l[end..], Q::Lit);
                        }
                        _ => acc.push(l, Q::Lit),
                    }
                }
                _ => self.expand_part(part, &mut acc, false, fields_mode)?,
            }
            first = false;
        }
        Ok(acc.finish())
    }

    fn expand_part(&mut self, part: &WordPart, acc: &mut Acc, quoted: bool, fields: bool) -> ExResult<()> {
        let eq = if quoted { Q::Quoted } else { Q::Exp };
        match part {
            WordPart::Lit(l) => acc.push(l, if quoted { Q::Quoted } else { Q::Lit }),
            WordPart::Quoted(l) => acc.push(l, Q::Quoted),
            WordPart::Escaped(c) => acc.push(&[*c], Q::Quoted),
            WordPart::DQuote(inner) => {
                if !(fields && !inner.is_empty() && inner.iter().all(is_list)) {
                    acc.mark_exists();
                }
                for p in inner {
                    self.expand_part(p, acc, true, fields)?;
                }
            }
            WordPart::CmdSub(prog, _) => {
                let out = self.command_output(prog);
                acc.push(&out, eq);
            }
            WordPart::Arith(w) => {
                let expr = self.expand_single(w)?;
                match crate::arith::eval(&expr, self) {
                    Ok(v) => acc.push(alloc::format!("{v}").as_bytes(), eq),
                    Err(e) => {
                        crate::error(format_args!("{}: {e}", text(&expr)));
                        return Err(ExpandError::Fatal);
                    }
                }
            }
            WordPart::Param(p) => self.expand_param(p, acc, quoted, fields)?,
            WordPart::ArrayLit(elems) => {
                // Outside an assignment: the text as written.
                let mut t = alloc::vec![b'('];
                for (i, e) in elems.iter().enumerate() {
                    if i > 0 {
                        t.push(b' ');
                    }
                    t.extend(word_text(e));
                }
                t.push(b')');
                acc.push(&t, if quoted { Q::Quoted } else { Q::Lit });
            }
            WordPart::ProcSub(prog, out) => {
                let path = self.procsub(prog, *out);
                acc.push(&path, Q::Quoted);
            }
        }
        Ok(())
    }

    /// `<(prog)` / `>(prog)`: run `prog` with a pipe on its standard output
    /// (or input) and name our end `/dev/fd/N`; the command that uses it
    /// inherits it, and it is closed when that command ends.
    fn procsub(&mut self, prog: &alloc::rc::Rc<Program>, out: bool) -> Vec<u8> {
        use slate_rt::{io, process};
        let Ok((r, w)) = process::pipe(0) else {
            crate::error(format_args!("pipe failed"));
            return Vec::new();
        };
        let Some(pid) = self.fork() else {
            let _ = io::close(r);
            let _ = io::close(w);
            return Vec::new();
        };
        let (mine, theirs) = if out { (w, r) } else { (r, w) };
        if pid == 0 {
            let _ = io::close(mine);
            let _ = process::dup2(theirs, if out { 0 } else { 1 });
            let _ = io::close(theirs);
            let res = self.run_program(prog);
            self.child_exit(res);
        }
        let _ = io::close(theirs);
        self.procsubs.push((mine, pid));
        alloc::format!("/dev/fd/{mine}").into_bytes()
    }

    /// An assignment's left side as text (`name`, `name[sub]`, with `+`
    /// for appending) and its value (an array literal encoded).
    pub fn expand_assign(&mut self, a: &Assign) -> ExResult<(Vec<u8>, Vec<u8>)> {
        let mut lhs = a.name.clone();
        if let Some(w) = &a.index {
            let sub = self.expand_single(w)?;
            lhs.push(b'[');
            lhs.extend(sub);
            lhs.push(b']');
        }
        if a.append {
            lhs.push(b'+');
        }
        let value = match a.value.as_slice() {
            [WordPart::ArrayLit(elems)] => self.expand_array_literal(elems)?,
            _ => self.expand_single(&a.value)?,
        };
        Ok((lhs, value))
    }

    /// An array literal's elements: `[key]=value` ones as written (no
    /// splitting), the others split and globbed into elements.
    fn expand_array_literal(&mut self, elems: &[Word]) -> ExResult<Vec<u8>> {
        let mut out = Vec::new();
        for e in elems {
            if let Some(WordPart::Lit(l)) = e.first()
                && l.first() == Some(&b'[')
                && let Some((keyw, after, part)) = crate::parser::subscript_end(e, 0, 1)
                && let WordPart::Lit(tail) = &e[part]
                && tail[after..].starts_with(b"=")
            {
                let mut valw: Word = Vec::new();
                if tail.len() > after + 1 {
                    valw.push(WordPart::Lit(tail[after + 1..].to_vec()));
                }
                valw.extend(e[part + 1..].iter().cloned());
                let key = self.expand_single(&keyw)?;
                let val = self.expand_single(&valw)?;
                out.push((Some(key), val));
                continue;
            }
            for f in self.expand_fields(e)? {
                out.push((None, f));
            }
        }
        Ok(crate::arrays::encode(&out))
    }

    /// A simple command's words: for the declaration built-ins, the
    /// arguments that are assignments expand as assignments do (no
    /// splitting or globbing, array literals kept).
    pub fn expand_command_words(&mut self, words: &[Word]) -> ExResult<Vec<Vec<u8>>> {
        let decl = words
            .first()
            .and_then(crate::parser::literal)
            .is_some_and(|n| matches!(n, b"declare" | b"typeset" | b"local" | b"export" | b"readonly"));
        if !decl {
            return self.expand_words(words);
        }
        let mut out = self.expand_fields(&words[0])?;
        for w in &words[1..] {
            match crate::parser::split_assign(w) {
                Some(a) => {
                    let (mut lhs, v) = self.expand_assign(&a)?;
                    lhs.push(b'=');
                    lhs.extend(v);
                    out.push(lhs);
                }
                None => out.extend(self.expand_fields(w)?),
            }
        }
        Ok(out)
    }

    /// `${a[@]}`-style lists: one field each ("..." and unquoted), or
    /// joined by IFS's first byte (`"${a[*]}"`) or a space.
    fn emit_list(&mut self, acc: &mut Acc, vals: &[Vec<u8>], quoted: bool, star: bool, fields: bool) {
        if (quoted && star) || !fields {
            let sep = if star { self.get_var(b"IFS").map_or(Some(b' '), |i| i.first().copied()) } else { Some(b' ') };
            let mut v = Vec::new();
            for (i, a) in vals.iter().enumerate() {
                if i > 0
                    && let Some(c) = sep
                {
                    v.push(c);
                }
                v.extend_from_slice(a);
            }
            if quoted {
                acc.mark_exists();
            }
            acc.push(&v, if quoted { Q::Quoted } else { Q::Exp });
            return;
        }
        for (i, a) in vals.iter().enumerate() {
            if i > 0 {
                acc.break_field();
            }
            acc.push(a, if quoted { Q::Quoted } else { Q::Exp });
        }
    }

    /// `${name[@]...}` and `${!name[@]}`: the array's values (or keys),
    /// with the operator applied to each.
    fn expand_array_param(&mut self, p: &Param, acc: &mut Acc, quoted: bool, fields: bool, star: bool) -> ExResult<()> {
        let mut vals = if p.indirect { self.element_keys(&p.name) } else { self.elements(&p.name) };
        match &p.op {
            ParamOp::Length => {
                acc.push(alloc::format!("{}", vals.len()).as_bytes(), if quoted { Q::Quoted } else { Q::Exp });
                return Ok(());
            }
            ParamOp::Default(w) | ParamOp::Alt(w) | ParamOp::Assign(w) | ParamOp::Error(w) => {
                let set = !vals.is_empty() && !(p.colon && vals.iter().all(|v| v.is_empty()));
                let alt = matches!(p.op, ParamOp::Alt(_));
                if set != alt {
                    if alt {
                        return Ok(());
                    }
                    for part in w {
                        self.expand_part(part, acc, quoted, fields)?;
                    }
                    return Ok(());
                }
                if alt {
                    for part in w {
                        self.expand_part(part, acc, quoted, fields)?;
                    }
                    return Ok(());
                }
            }
            ParamOp::Substr(off, len) => {
                let n = vals.len() as i64;
                let o = self.arith_word(off)?;
                let start = if o < 0 { (n + o).max(0) } else { o.min(n) };
                let end = match len {
                    Some(l) => {
                        let l = self.arith_word(l)?;
                        if l < 0 { (n + l).max(start) } else { (start + l).min(n) }
                    }
                    None => n,
                };
                vals = vals[start as usize..end as usize].to_vec();
            }
            ParamOp::RemovePrefix(w, longest) | ParamOp::RemoveSuffix(w, longest) => {
                let pat = self.expand_pattern(w)?;
                let suffix = matches!(p.op, ParamOp::RemoveSuffix(..));
                for v in vals.iter_mut() {
                    let lens: Vec<usize> =
                        if *longest { (0..=v.len()).rev().collect() } else { (0..=v.len()).collect() };
                    for n in lens {
                        let (cand, rest) =
                            if suffix { (&v[v.len() - n..], &v[..v.len() - n]) } else { (&v[..n], &v[n..]) };
                        if glob::matches(&pat, cand) {
                            *v = rest.to_vec();
                            break;
                        }
                    }
                }
            }
            ParamOp::Replace { pat, rep, all, anchor } => {
                let pat = self.expand_pattern(pat)?;
                let rep = self.expand_single(rep)?;
                for v in vals.iter_mut() {
                    *v = replace(v, &pat, &rep, *all, *anchor);
                }
            }
            ParamOp::Case(upper, all) => {
                for v in vals.iter_mut() {
                    for (i, c) in v.iter_mut().enumerate() {
                        if i > 0 && !all {
                            break;
                        }
                        *c = if *upper { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() };
                    }
                }
            }
            ParamOp::Get | ParamOp::Names(_) => {}
        }
        self.emit_list(acc, &vals, quoted, star, fields);
        Ok(())
    }

    fn expand_param(&mut self, p: &Param, acc: &mut Acc, quoted: bool, fields: bool) -> ExResult<()> {
        let eq = if quoted { Q::Quoted } else { Q::Exp };
        if let ParamOp::Names(star) = p.op {
            let names: Vec<Vec<u8>> =
                self.vars.iter().filter(|(n, v)| n.starts_with(&p.name) && !v.unset).map(|(n, _)| n.clone()).collect();
            self.emit_list(acc, &names, quoted, star, fields);
            return Ok(());
        }
        // Arrays (bash): `${a[@]}`, `${a[*]}`, `${!a[@]}`, `${a[sub]}`.
        let sub_text = p.index.as_ref().map(word_text);
        match sub_text.as_deref() {
            Some(b"@") => return self.expand_array_param(p, acc, quoted, fields, false),
            Some(b"*") => return self.expand_array_param(p, acc, quoted, fields, true),
            _ => {}
        }
        // `${!ref}` of a name reference: the name it holds.
        if p.indirect && p.index.is_none() && p.op == ParamOp::Get && self.is_nameref(&p.name) {
            let v = self.vars.get(&p.name).map(|v| v.value.clone()).unwrap_or_default();
            acc.push(&v, eq);
            return Ok(());
        }
        // `${!name}`: the variable `name` names.
        let indirect_name;
        let name: &[u8] = if p.indirect {
            indirect_name = self.param(&p.name).unwrap_or_default();
            if let Some((n, sub)) = crate::shell::split_subscript(&indirect_name) {
                let v = self.get_elem(n, sub);
                if let Some(v) = v {
                    acc.push(&v, eq);
                }
                return Ok(());
            }
            &indirect_name
        } else {
            p.name.as_slice()
        };
        // "$@" and $@/$*: one field per positional parameter.
        if (name == b"@" || (name == b"*" && !quoted)) && p.op == ParamOp::Get {
            let ps = self.positional.clone();
            if quoted && fields {
                if ps.is_empty() {
                    return Ok(());
                }
                for (i, a) in ps.iter().enumerate() {
                    if i > 0 {
                        acc.break_field();
                    }
                    acc.push(a, Q::Quoted);
                }
                return Ok(());
            }
            if !quoted && fields {
                for (i, a) in ps.iter().enumerate() {
                    if i > 0 {
                        acc.break_field();
                    }
                    acc.push(a, Q::Exp);
                }
                return Ok(());
            }
        }
        let value = match &p.index {
            Some(w) => {
                let sub = self.expand_single(w)?;
                self.get_elem(name, &sub)
            }
            None => self.param(name),
        };
        let set = match &value {
            None => false,
            Some(v) => !(p.colon && v.is_empty()),
        };
        match &p.op {
            ParamOp::Get | ParamOp::Names(_) => match value {
                Some(v) => acc.push(&v, eq),
                None if self.opts.nounset && !matches!(name, b"@" | b"*") => {
                    crate::error(format_args!("{}: unbound variable", text(name)));
                    return Err(ExpandError::Fatal);
                }
                None => {}
            },
            ParamOp::Length if matches!(name, b"@" | b"*") => {
                acc.push(alloc::format!("{}", self.positional.len()).as_bytes(), eq);
            }
            ParamOp::Length => {
                let n = value.as_ref().map_or(0, |v| String::from_utf8_lossy(v).chars().count());
                acc.push(alloc::format!("{n}").as_bytes(), eq);
            }
            ParamOp::Default(w) => {
                if set {
                    acc.push(&value.unwrap(), eq);
                } else {
                    for part in w {
                        self.expand_part(part, acc, quoted, fields)?;
                    }
                }
            }
            ParamOp::Assign(w) => {
                if set {
                    acc.push(&value.unwrap(), eq);
                } else {
                    let v = self.expand_single(w)?;
                    if !crate::parser::is_name(name) {
                        crate::error(format_args!("${}: cannot assign in this way", text(name)));
                        return Err(ExpandError::Fatal);
                    }
                    self.set_var(name, &v);
                    acc.push(&v, eq);
                }
            }
            ParamOp::Error(w) => {
                if set {
                    acc.push(&value.unwrap(), eq);
                } else {
                    let msg = self.expand_single(w)?;
                    let msg = if msg.is_empty() { b"parameter null or not set".to_vec() } else { msg };
                    crate::error(format_args!("{}: {}", text(name), text(&msg)));
                    return Err(ExpandError::Fatal);
                }
            }
            ParamOp::Alt(w) => {
                if set {
                    for part in w {
                        self.expand_part(part, acc, quoted, fields)?;
                    }
                }
            }
            ParamOp::RemovePrefix(w, longest) | ParamOp::RemoveSuffix(w, longest) => {
                let v = value.unwrap_or_default();
                let pat = self.expand_pattern(w)?;
                let suffix = matches!(p.op, ParamOp::RemoveSuffix(..));
                let lens: Vec<usize> = if *longest { (0..=v.len()).rev().collect() } else { (0..=v.len()).collect() };
                let mut result = v.clone();
                for n in lens {
                    let (cand, rest) = if suffix { (&v[v.len() - n..], &v[..v.len() - n]) } else { (&v[..n], &v[n..]) };
                    if glob::matches(&pat, cand) {
                        result = rest.to_vec();
                        break;
                    }
                }
                acc.push(&result, eq);
            }
            ParamOp::Replace { pat, rep, all, anchor } => {
                let v = value.unwrap_or_default();
                let pat = self.expand_pattern(pat)?;
                let rep = self.expand_single(rep)?;
                acc.push(&replace(&v, &pat, &rep, *all, *anchor), eq);
            }
            ParamOp::Substr(off, len) => {
                let v = value.unwrap_or_default();
                let chars: Vec<char> = String::from_utf8_lossy(&v).chars().collect();
                let n = chars.len() as i64;
                let o = self.arith_word(off)?;
                let start = if o < 0 { (n + o).max(0) } else { o.min(n) };
                let end = match len {
                    Some(l) => {
                        let l = self.arith_word(l)?;
                        if l < 0 { (n + l).max(start) } else { (start + l).min(n) }
                    }
                    None => n,
                };
                let s: String = chars[start as usize..end as usize].iter().collect();
                acc.push(s.as_bytes(), eq);
            }
            ParamOp::Case(upper, all) => {
                let v = value.unwrap_or_default();
                let mut out = v.clone();
                for (i, c) in out.iter_mut().enumerate() {
                    if i > 0 && !all {
                        break;
                    }
                    *c = if *upper { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() };
                }
                acc.push(&out, eq);
            }
        }
        Ok(())
    }

    fn arith_word(&mut self, w: &Word) -> ExResult<i64> {
        let e = self.expand_single(w)?;
        crate::arith::eval(&e, self).map_err(|m| {
            crate::error(format_args!("{}: {m}", text(&e)));
            ExpandError::Fatal
        })
    }
}

/// `${v/pat/rep}`: the leftmost longest match (all of them with `all`).
fn replace(v: &[u8], pat: &[(u8, bool)], rep: &[u8], all: bool, anchor: u8) -> Vec<u8> {
    match anchor {
        b'#' => {
            for n in (0..=v.len()).rev() {
                if glob::matches(pat, &v[..n]) {
                    let mut o = rep.to_vec();
                    o.extend_from_slice(&v[n..]);
                    return o;
                }
            }
            return v.to_vec();
        }
        b'%' => {
            for n in 0..=v.len() {
                if glob::matches(pat, &v[n..]) {
                    let mut o = v[..n].to_vec();
                    o.extend_from_slice(rep);
                    return o;
                }
            }
            return v.to_vec();
        }
        _ => {}
    }
    if pat.is_empty() {
        return v.to_vec();
    }
    let mut out = Vec::new();
    let mut i = 0;
    let mut done = false;
    while i < v.len() {
        if !done {
            let found = (i + 1..=v.len()).rev().find(|&e| glob::matches(pat, &v[i..e]));
            if let Some(e) = found {
                out.extend_from_slice(rep);
                i = e;
                if !all {
                    done = true;
                }
                continue;
            }
        }
        out.push(v[i]);
        i += 1;
    }
    out
}
