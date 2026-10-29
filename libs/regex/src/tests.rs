// SPDX-License-Identifier: MIT OR Apache-2.0

use alloc::vec::Vec;

use super::*;

fn ere(p: &str) -> Regex {
    Regex::new(p.as_bytes(), Options::extended()).unwrap()
}

fn bre(p: &str) -> Regex {
    Regex::new(p.as_bytes(), Options::basic()).unwrap()
}

/// The whole match as text.
fn m(r: &Regex, t: &str) -> Option<std::string::String> {
    r.find_at(t.as_bytes(), 0).map(|c| {
        let (a, b) = c[0].unwrap();
        std::string::String::from(&t[a..b])
    })
}

fn groups(r: &Regex, t: &str) -> Vec<Option<std::string::String>> {
    let c = r.find_at(t.as_bytes(), 0).unwrap();
    c.iter().map(|g| g.map(|(a, b)| std::string::String::from(&t[a..b]))).collect()
}

#[test]
fn literals_and_classes() {
    assert_eq!(m(&ere("abc"), "xxabcxx").as_deref(), Some("abc"));
    assert_eq!(m(&ere("a.c"), "abc").as_deref(), Some("abc"));
    assert_eq!(m(&ere("[0-9]+"), "ab123c").as_deref(), Some("123"));
    assert_eq!(m(&ere("[^a-c]+"), "abcdefa").as_deref(), Some("def"));
    assert_eq!(m(&ere("[[:upper:]][[:digit:]]"), "aB3").as_deref(), Some("B3"));
    assert_eq!(m(&ere("[]a]+"), "x]a]b").as_deref(), Some("]a]"));
    assert_eq!(m(&ere("[a-]+"), "-a-b").as_deref(), Some("-a-"));
    assert_eq!(m(&ere("x"), "abc"), None);
}

#[test]
fn leftmost_longest() {
    assert_eq!(m(&ere("x|xy"), "xyz").as_deref(), Some("xy"));
    assert_eq!(m(&ere("a*"), "baaa").as_deref(), Some(""));
    assert_eq!(m(&ere("a+"), "baaa").as_deref(), Some("aaa"));
    assert_eq!(m(&ere("(a|ab)(c|bcd)"), "abcd").as_deref(), Some("abcd"));
    assert_eq!(m(&ere("b|abc"), "abc").as_deref(), Some("abc"));
}

#[test]
fn repetition() {
    assert_eq!(m(&ere("a{2,3}"), "aaaa").as_deref(), Some("aaa"));
    assert_eq!(m(&ere("a{2}"), "aaaa").as_deref(), Some("aa"));
    assert_eq!(m(&ere("a{2,}"), "aaaa").as_deref(), Some("aaaa"));
    assert_eq!(m(&ere("ab?c"), "ac").as_deref(), Some("ac"));
    assert_eq!(m(&bre("a\\{2\\}"), "aaa").as_deref(), Some("aa"));
    assert_eq!(m(&bre("a\\+"), "baa").as_deref(), Some("aa"));
    assert_eq!(m(&bre("ab\\?c"), "ac").as_deref(), Some("ac"));
    assert_eq!(m(&ere("(a*)*"), "aaa").as_deref(), Some("aaa"));
    assert_eq!(m(&ere("(a*)+b"), "aab").as_deref(), Some("aab"));
}

#[test]
fn bre_specials() {
    // `*` first, `+` and `{` are ordinary in a BRE.
    assert_eq!(m(&bre("*a"), "x*a").as_deref(), Some("*a"));
    assert_eq!(m(&bre("a+"), "aa+").as_deref(), Some("a+"));
    assert_eq!(m(&bre("a{2}"), "a{2}").as_deref(), Some("a{2}"));
    assert_eq!(m(&bre("^*x"), "*x").as_deref(), Some("*x"));
    // `^`/`$` anchor only at the ends.
    assert_eq!(m(&bre("a^b"), "a^b").as_deref(), Some("a^b"));
    assert_eq!(m(&bre("a$b"), "a$b").as_deref(), Some("a$b"));
    assert_eq!(m(&bre("^ab$"), "ab").as_deref(), Some("ab"));
    assert_eq!(m(&bre("\\(ab\\)*c"), "ababc").as_deref(), Some("ababc"));
    assert_eq!(m(&bre("a\\|b"), "b").as_deref(), Some("b"));
}

#[test]
fn ere_specials() {
    assert_eq!(m(&ere("a{"), "a{").as_deref(), Some("a{"));
    assert_eq!(m(&ere("a)"), "a)").as_deref(), Some("a)"));
    assert_eq!(m(&ere("\\(x\\)"), "(x)").as_deref(), Some("(x)"));
    assert_eq!(m(&ere("^a|b$"), "cb").as_deref(), Some("b"));
}

#[test]
fn anchors_and_words() {
    assert_eq!(m(&ere("^b"), "ab"), None);
    assert_eq!(m(&ere("a$"), "ab"), None);
    assert_eq!(m(&ere("\\bfoo\\b"), "a foo b").as_deref(), Some("foo"));
    assert_eq!(m(&ere("\\<o"), "foo oo").as_deref(), Some("o"));
    assert_eq!(ere("\\<o").find_at(b"foo oo", 0).unwrap()[0], Some((4, 5)));
    assert_eq!(m(&ere("o\\>"), "foo").as_deref(), Some("o"));
    assert_eq!(m(&ere("\\w+"), "  ab_1 ").as_deref(), Some("ab_1"));
    assert_eq!(m(&ere("\\s+"), "a \t b").as_deref(), Some(" \t "));
    assert_eq!(m(&ere("\\Bo"), "foo").as_deref(), Some("o"));
    let r = Regex::new(b"^b", Options { newline: true, ..Options::extended() }).unwrap();
    assert_eq!(r.find_at(b"a\nb", 0).unwrap()[0], Some((2, 3)));
    assert!(ere("^a").find_from(b"ab", 0, true).is_none());
}

#[test]
fn captures_and_backrefs() {
    assert_eq!(
        groups(&ere("(a+)(b+)"), "xaabbb"),
        alloc::vec![Some("aabbb".into()), Some("aa".into()), Some("bbb".into())]
    );
    assert_eq!(groups(&ere("(a)|b"), "b"), alloc::vec![Some("b".into()), None]);
    assert_eq!(groups(&ere("(a|b)*"), "abab")[1].as_deref(), Some("b"));
    assert_eq!(m(&bre("\\(a*\\)b\\1"), "aabaa").as_deref(), Some("aabaa"));
    assert_eq!(m(&bre("\\(.\\)\\1"), "abccd").as_deref(), Some("cc"));
    assert_eq!(m(&ere("(.)(.)\\2\\1"), "xabbay").as_deref(), Some("abba"));
    assert_eq!(m(&bre("\\(a*\\)*\\1"), "aaa").as_deref(), Some("aaa"));
}

#[test]
fn case_folding() {
    let r = Regex::new(b"hello [a-c]", Options { icase: true, ..Options::extended() }).unwrap();
    assert_eq!(m(&r, "say HeLLo B").as_deref(), Some("HeLLo B"));
    let r = Regex::new(b"\\(ab\\)\\1", Options { icase: true, ..Options::basic() }).unwrap();
    assert_eq!(m(&r, "abAB").as_deref(), Some("abAB"));
}

#[test]
fn errors() {
    for (p, e) in [
        ("a\\(", "Unmatched ( or \\("),
        ("[a", "Unmatched [, [^, [:, [., or [="),
        ("a\\", "Trailing backslash"),
        ("\\1", "Invalid back reference"),
        ("[z-a]", "Invalid range end"),
        ("[[:foo:]]", "Invalid character class name"),
        ("a\\{1", "Unmatched \\{"),
    ] {
        assert_eq!(Regex::new(p.as_bytes(), Options::basic()).unwrap_err().0, e, "{p}");
    }
    assert_eq!(Regex::new(b"(a", Options::extended()).unwrap_err().0, "Unmatched ( or \\(");
    assert_eq!(Regex::new(b"a{2,1}", Options::extended()).unwrap_err().0, "Invalid content of \\{\\}");
}

#[test]
fn empty_and_iteration() {
    let r = ere("a*");
    let t = b"baab";
    let mut pos = 0;
    let mut found = Vec::new();
    while let Some(c) = r.find_at(t, pos) {
        let (a, b) = c[0].unwrap();
        found.push((a, b));
        pos = if b > a { b } else { b + 1 };
        if pos > t.len() {
            break;
        }
    }
    assert_eq!(found, alloc::vec![(0, 0), (1, 3), (3, 3), (4, 4)]);
    assert_eq!(m(&ere(""), "abc").as_deref(), Some(""));
    // Big but linear.
    let long = "a".repeat(20000) + "b";
    assert_eq!(m(&ere("(a|aa)*b"), &long).map(|s| s.len()), Some(20001));
}

#[test]
fn whole_words_and_lines() {
    let w = |p: &str| Regex::new(p.as_bytes(), Options { whole: Whole::Word, ..Options::extended() }).unwrap();
    assert_eq!(m(&w("foo"), "foo_bar foo-x").as_deref(), Some("foo"));
    assert_eq!(w("foo").find_at(b"foo_bar foo-x", 0).unwrap()[0], Some((8, 11)));
    assert_eq!(m(&w("o*"), "foo bar"), None);
    let x = Regex::new(b"a|ab", Options { whole: Whole::Line, ..Options::extended() }).unwrap();
    assert!(x.is_match(b"ab") && !x.is_match(b"abc"));
    let l = Regex::literal(b"a.b", Options { icase: true, ..Options::basic() });
    assert!(l.is_match(b"xA.By") && !l.is_match(b"axb"));
}

/// The literal prefilter and the DFA give what the Pike VM alone gives,
/// over random patterns and texts (anchors, word assertions, classes,
/// repeats, alternation, groups, case folding, REG_NEWLINE, REG_NOTBOL).
#[test]
fn fast_paths_agree_with_the_pike_vm() {
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut rnd = |n: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % n as u64) as usize
    };
    const ATOMS: &[&str] = &[
        "a", "b", "ab", "abc", "ba", "[ab]", "[^a]", ".", "x", "A", "\\w", "\\W", "[0-9]", " ", "\\n", "é", "[à-ü]",
        "[^é]", "É",
    ];
    const LOOKS: &[&str] = &["^", "$", "\\b", "\\B", "\\<", "\\>"];
    let texts: Vec<&[u8]> = alloc::vec![
        b"",
        b"a",
        b"ab",
        b"abc abc",
        b"xx ab\nba",
        b"Ab aB",
        b"bbbbbbba",
        b"a1b2 c3",
        b"\nab\n",
        b"zzzzzzzzzzzzzzzzzzzzabc",
        b"word, words; WORDS",
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaab",
        "café naïve".as_bytes(),
        "ÉCOLE é ü".as_bytes(),
        b"bad \xC3 byte \xff",
    ];
    for round in 0..3000 {
        let mut p = std::string::String::new();
        let parts = 1 + rnd(4);
        for _ in 0..parts {
            match rnd(6) {
                0 => p.push_str(LOOKS[rnd(LOOKS.len())]),
                1 => {
                    p.push('(');
                    p.push_str(ATOMS[rnd(ATOMS.len())]);
                    p.push('|');
                    p.push_str(ATOMS[rnd(ATOMS.len())]);
                    p.push(')');
                }
                _ => p.push_str(ATOMS[rnd(ATOMS.len())]),
            }
            match rnd(5) {
                0 => p.push('*'),
                1 => p.push('+'),
                2 => p.push('?'),
                _ => {}
            }
        }
        let opts = Options {
            syntax: Syntax::Extended,
            icase: rnd(3) == 0,
            newline: rnd(3) == 0,
            whole: [Whole::Any, Whole::Any, Whole::Word, Whole::Line][rnd(4)],
            utf8: rnd(2) == 0,
            ..Options::default()
        };
        let Ok(r) = Regex::new(p.as_bytes(), opts) else { continue };
        for t in &texts {
            for start in 0..=t.len().min(3) {
                let not_bol = round % 2 == 1;
                let fast = r.find_from(t, start, not_bol);
                let slow = r.find_slow(t, start, not_bol);
                // A pure literal reports only the whole match.
                let fast0 = fast.as_ref().map(|c| c[0]);
                let slow0 = slow.as_ref().map(|c| c[0]);
                assert_eq!(
                    fast0,
                    slow0,
                    "pattern {p:?} {opts:?} text {:?} start {start}",
                    std::string::String::from_utf8_lossy(t)
                );
                if !r.pure {
                    assert_eq!(
                        fast,
                        slow,
                        "captures: pattern {p:?} text {:?}",
                        std::string::String::from_utf8_lossy(t)
                    );
                }
                if start == 0 && !not_bol {
                    assert_eq!(
                        r.is_match(t),
                        slow.is_some(),
                        "is_match: pattern {p:?} {opts:?} text {:?}",
                        std::string::String::from_utf8_lossy(t)
                    );
                }
                let at = r.match_at(t, start).map(|c| c[0]);
                let ctx = vm::Ctx { text: t, newline: r.newline, not_bol: false, icase: r.icase, utf8: r.utf8 };
                let mut sc = vm::Scratch::new(&r.prog, r.groups);
                let slow_at = vm::pike(&r.prog, r.groups, &ctx, start, None, true, &mut sc).map(|c| c[0]);
                assert_eq!(
                    at,
                    slow_at,
                    "match_at: pattern {p:?} text {:?} at {start}",
                    std::string::String::from_utf8_lossy(t)
                );
            }
        }
    }
}

/// Back-references with exponentially many paths: states already tried
/// aren't tried again, so the answer comes at once (exploring every path
/// took the whole step budget at each start position, which then gave up
/// and said no match).
#[test]
fn backtracking_remembers_what_it_tried() {
    let a40 = "a".repeat(40);
    // The literal is there, the match is not: every path must fail.
    let r = ere("(a|a)*\\1y$");
    assert_eq!(m(&r, &std::format!("{a40}yq")), None);
    assert_eq!(m(&r, &std::format!("{a40}y")).as_deref(), Some(std::format!("{a40}y").as_str()));
    let r = ere("^(a*)*(b|\\1)$");
    assert_eq!(m(&r, &std::format!("{a40}b")).as_deref(), Some(std::format!("{a40}b").as_str()));
    assert_eq!(m(&r, &std::format!("{a40}c")), None);
    let r = bre("\\(.*\\)x\\1");
    assert_eq!(groups(&r, "abxab"), [Some("abxab".into()), Some("ab".into())]);
}

/// In a UTF-8 locale, characters are matched whole.
#[test]
fn utf8_characters() {
    let u = |p: &str, icase: bool| {
        Regex::new(p.as_bytes(), Options { syntax: Syntax::Extended, icase, utf8: true, ..Options::default() }).unwrap()
    };
    assert_eq!(m(&u("caf.", false), "café!").as_deref(), Some("café"));
    assert_eq!(m(&u("^.{4}$", false), "café").as_deref(), Some("café"));
    assert_eq!(m(&u("é+", false), "xéééy").as_deref(), Some("ééé"));
    assert_eq!(m(&u("[à-ü]+", false), "naïve").as_deref(), Some("ï"));
    assert_eq!(m(&u("[^a-z]", false), "abcé").as_deref(), Some("é"));
    assert_eq!(m(&u("[[:alpha:]]+", false), "1 Ωμέγα 2").as_deref(), Some("Ωμέγα"));
    assert_eq!(m(&u("[[:upper:]]", false), "aÉb").as_deref(), Some("É"));
    assert_eq!(m(&u("\\w+", false), " déjà-vu").as_deref(), Some("déjà"));
    assert_eq!(m(&u("ÉCOLE", true), "une école").as_deref(), Some("école"));
    assert_eq!(m(&u("[é]", true), "É").as_deref(), Some("É"));
    assert!(u(".", false).find_at(b"\xff", 0).is_none(), "an invalid byte is no character");
    assert_eq!(m(&u("\\bcaf\\b", false), "café caf"), Some("caf".into()));
    let f = Regex::literal("ÉTÉ".as_bytes(), Options { icase: true, utf8: true, ..Options::default() });
    assert_eq!(m(&f, "un été").as_deref(), Some("été"));
    // Without utf8, the same pattern is bytes.
    assert_eq!(m(&ere("^.{4}$"), "café"), None);
}

/// Perl's patterns (grep -P): the first match in priority order, and
/// PCRE's syntax.
#[test]
fn perl_patterns() {
    let p = |pat: &str| Regex::perl(pat.as_bytes(), Options::default()).unwrap();
    let pe = |pat: &str| Regex::perl(pat.as_bytes(), Options::default()).unwrap_err().0;
    assert_eq!(m(&p("a|ab"), "abc").as_deref(), Some("a"));
    assert_eq!(m(&p("\\d+"), "foo=12 bar").as_deref(), Some("12"));
    assert_eq!(m(&p("bar=\\K\\d+"), "foo=1 bar=345").as_deref(), Some("345"));
    assert_eq!(m(&p("(?<=foo=)\\d+"), "bar=7 foo=12").as_deref(), Some("12"));
    assert_eq!(m(&p("(?<=a|bc)x"), "bcx").as_deref(), Some("x"));
    assert_eq!(m(&p("b(?!c)"), "bc bar").as_deref(), Some("b"));
    assert_eq!(m(&p("\\w+?="), "foo=1").as_deref(), Some("foo="));
    assert_eq!(m(&p("a{2,}?"), "aaaa").as_deref(), Some("aa"));
    assert_eq!(m(&p("(?i)abc"), "xABC").as_deref(), Some("ABC"));
    assert_eq!(m(&p("a(?i:b)c"), "aBc aBC").as_deref(), Some("aBc"));
    assert_eq!(m(&p("(?:ab)+"), "ababx").as_deref(), Some("abab"));
    assert_eq!(m(&p("(?<x>ab)\\k<x>"), "abab").as_deref(), Some("abab"));
    assert_eq!(m(&p("(?P<x>a)(?P=x)"), "aa").as_deref(), Some("aa"));
    assert_eq!(m(&p("(a)\\g{-1}"), "aa").as_deref(), Some("aa"));
    assert_eq!(m(&p("\\Qx.y\\E"), "xzy x.y").as_deref(), Some("x.y"));
    assert_eq!(m(&p("(?x) a b c # comment"), "abc").as_deref(), Some("abc"));
    assert_eq!(m(&p("a++b"), "aaab").as_deref(), Some("aaab"));
    assert_eq!(m(&p("a++a"), "aaaa"), None, "possessive gives nothing back");
    assert_eq!(m(&p("(?>a+)a"), "aaa"), None);
    assert_eq!(m(&p("\\x41\\x{42}\\o{103}\\cA"), "ABC\u{1}").as_deref(), Some("ABC\u{1}"));
    assert_eq!(m(&p("[\\d=]+"), "x=12").as_deref(), Some("=12"));
    assert_eq!(m(&p("[^\\W\\d]+"), "12ab3").as_deref(), Some("ab"));
    assert_eq!(m(&p("[[:alpha:]-]+"), "a-b c").as_deref(), Some("a-b"));
    assert_eq!(m(&p("\\p{L}+"), "12abc").as_deref(), Some("abc"));
    assert_eq!(m(&p("\\bbar\\b"), "foobar bar").as_deref(), Some("bar"));
    assert_eq!(m(&p("(a)|b\\1"), "b a").as_deref(), Some("a"));
    assert_eq!(pe("("), "missing closing parenthesis");
    assert_eq!(pe("a)"), "unmatched closing parenthesis");
    assert_eq!(pe("*a"), "quantifier does not follow a repeatable item");
    assert_eq!(pe("[ab"), "missing terminating ] for character class");
    assert_eq!(pe("(?<=a+)b"), "length of lookbehind assertion is not limited");
    assert!(pe("(a)?(?(1)x|y)").contains("not supported"));
    assert_eq!(pe("\\q"), "unrecognized character follows \\");
}

/// The DFA's "no match" for Perl's patterns and back-references comes
/// from a looser pattern; it must never hide a match the backtracker
/// alone finds.
#[test]
fn relaxed_dfa_hides_no_match() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut rnd = |n: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % n as u64) as usize
    };
    const ATOMS: &[&str] = &[
        "a",
        "b",
        "ab",
        "[ab]",
        ".",
        "\\d",
        "\\w",
        "x",
        "(a|b)",
        "(?=a)",
        "(?!b)",
        "(?<=a)",
        "(?<!b)",
        "(?>a+)",
        "a++",
        "a*?",
        "\\K",
        "(a)\\1",
        "(?<n>b)\\k<n>",
    ];
    let texts: [&[u8]; 8] = [b"", b"a", b"ab", b"aab", b"ba", b"xaab1", b"abab", b"bbaaab x"];
    for _ in 0..3000 {
        let mut p = std::string::String::new();
        for _ in 0..1 + rnd(4) {
            p.push_str(ATOMS[rnd(ATOMS.len())]);
            match rnd(5) {
                0 => p.push('*'),
                1 => p.push('+'),
                2 => p.push('?'),
                _ => {}
            }
        }
        let Ok(r) = Regex::perl(p.as_bytes(), Options::default()) else { continue };
        for t in texts {
            for start in 0..=t.len() {
                let ctx = vm::Ctx { text: t, newline: false, not_bol: false, icase: false, utf8: false };
                let slow = vm::backtrack(&r.prog, r.groups, &ctx, start, r.anchored, true, None);
                assert_eq!(
                    r.find_from(t, start, false),
                    slow,
                    "pattern {p:?} text {:?} at {start}",
                    std::string::String::from_utf8_lossy(t)
                );
            }
        }
    }
}
