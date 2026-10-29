// SPDX-License-Identifier: MIT OR Apache-2.0

use std::string::String;
use std::vec::Vec;

use super::*;

fn file(s: &str) -> Node {
    Node::File { data: s.as_bytes().to_vec(), mode: 0o644, uid: 0, gid: 0 }
}

fn tree(files: &[(&str, Node)]) -> Tree {
    files.iter().map(|(p, n)| (String::from(*p), n.clone())).collect()
}

fn put<'a>(o: &'a Outcome, path: &str) -> Option<&'a Node> {
    o.changes.iter().find_map(|c| match c {
        Change::Put(p, n) if p == path => Some(n),
        _ => None,
    })
}

fn text_of(n: &Node) -> String {
    match n {
        Node::File { data, .. } => String::from_utf8(data.clone()).unwrap(),
        _ => panic!("not a file"),
    }
}

const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\n# system accounts\nsshd:x:22:22::/var/empty:/bin/false\n";

#[test]
fn one_sided_changes_come_across() {
    let base = tree(&[("hostname", file("slate\n")), ("motd", file("hello\n")), ("old", file("x\n"))]);
    let ours = tree(&[
        ("hostname", file("slate\n")),
        ("motd", file("hello\n")),
        ("old", file("x\n")),
        ("ours-new", file("o\n")),
    ]);
    let theirs = tree(&[
        (
            "hostname",
            file(
                "desk
",
            ),
        ),
        ("motd", file("hello\n")),
        ("theirs-new", file("t\n")),
    ]);
    let o = merge(&base, &ours, &theirs);
    assert_eq!(
        put(&o, "hostname"),
        Some(&file(
            "desk
"
        ))
    );
    assert_eq!(put(&o, "theirs-new"), Some(&file("t\n")));
    assert!(o.changes.contains(&Change::Remove(String::from("old"))));
    // What ours added stays (no change for it), and nothing conflicts.
    assert!(put(&o, "ours-new").is_none() && !o.changes.contains(&Change::Remove(String::from("ours-new"))));
    assert!(o.conflicts.is_empty());
}

#[test]
fn accounts_added_on_both_sides_merge_by_record() {
    let base = tree(&[("passwd", file(PASSWD))]);
    let ours = tree(&[("passwd", file(&std::format!("{PASSWD}ntp:x:123:123::/var/empty:/bin/false\n")))]);
    let theirs = tree(&[(
        "passwd",
        file(
            &(PASSWD.replace("root:/root:/bin/sh", "root:/root:/bin/chalk")
                + "ada:x:1000:1000:Ada:/home/ada:/bin/sh\n"),
        ),
    )]);
    let o = merge(&base, &ours, &theirs);
    assert_eq!(
        text_of(put(&o, "passwd").unwrap()),
        "root:x:0:0:root:/root:/bin/chalk\n# system accounts\nsshd:x:22:22::/var/empty:/bin/false\n\
         ntp:x:123:123::/var/empty:/bin/false\nada:x:1000:1000:Ada:/home/ada:/bin/sh\n"
    );
    assert_eq!(o.merged, ["passwd"]);
    // A user theirs removed goes; a password both changed takes theirs.
    let base = tree(&[("shadow", file("root:!:1::::::\nbob:$6$old:1::::::\nada:$6$a:1::::::\n"))]);
    let ours = tree(&[("shadow", file("root:$6$ours:2::::::\nbob:$6$old:1::::::\nada:$6$a:1::::::\n"))]);
    let theirs = tree(&[("shadow", file("root:$6$theirs:3::::::\nada:$6$a:1::::::\n"))]);
    let o = merge(&base, &ours, &theirs);
    assert_eq!(text_of(put(&o, "shadow").unwrap()), "root:$6$theirs:3::::::\nada:$6$a:1::::::\n");
}

#[test]
fn text_merges_line_by_line() {
    let base = "# sshd_config\nPort 22\nPermitRootLogin prohibit-password\nX11Forwarding no\n";
    let ours = "# sshd_config\nPort 22\nPermitRootLogin prohibit-password\nX11Forwarding no\nMaxSessions 4\n";
    let theirs = "# sshd_config\nPort 2222\nPermitRootLogin prohibit-password\nX11Forwarding no\n";
    let o = merge(
        &tree(&[("ssh/sshd_config", file(base))]),
        &tree(&[("ssh/sshd_config", file(ours))]),
        &tree(&[("ssh/sshd_config", file(theirs))]),
    );
    assert_eq!(
        text_of(put(&o, "ssh/sshd_config").unwrap()),
        "# sshd_config\nPort 2222\nPermitRootLogin prohibit-password\nX11Forwarding no\nMaxSessions 4\n"
    );
    assert!(o.conflicts.is_empty());
}

#[test]
fn a_real_conflict_keeps_ours_and_saves_theirs() {
    let base = tree(&[
        ("hosts", file("127.0.0.1 localhost\n")),
        ("blob", Node::File { data: std::vec![0, 1], mode: 0o600, uid: 5, gid: 5 }),
    ]);
    let ours = tree(&[
        ("hosts", file("127.0.0.1 ours\n")),
        ("blob", Node::File { data: std::vec![0, 2], mode: 0o600, uid: 5, gid: 5 }),
    ]);
    let theirs = tree(&[
        ("hosts", file("127.0.0.1 theirs\n")),
        ("blob", Node::File { data: std::vec![0, 3], mode: 0o600, uid: 5, gid: 5 }),
    ]);
    let o = merge(&base, &ours, &theirs);
    assert_eq!(o.conflicts, ["blob", "hosts"]);
    assert_eq!(put(&o, "hosts.slate-merge"), Some(&file("127.0.0.1 theirs\n")));
    assert!(put(&o, "hosts").is_none());
    assert_eq!(put(&o, "blob.slate-merge"), Some(&Node::File { data: std::vec![0, 3], mode: 0o600, uid: 5, gid: 5 }));
    // A change against a removal conflicts too.
    let o = merge(&tree(&[("a", file("1\n"))]), &tree(&[]), &tree(&[("a", file("2\n"))]));
    assert_eq!(o.conflicts, ["a"]);
}

#[test]
fn modes_and_owners_are_versions_too() {
    let mk = |mode, uid| Node::File { data: b"k\n".to_vec(), mode, uid, gid: 0 };
    let o = merge(&tree(&[("key", mk(0o644, 0))]), &tree(&[("key", mk(0o644, 0))]), &tree(&[("key", mk(0o600, 0))]));
    assert_eq!(put(&o, "key"), Some(&mk(0o600, 0)));
    // Theirs' mode and ours' text change, merged.
    let base = Node::File { data: b"a\nb\n".to_vec(), mode: 0o644, uid: 0, gid: 0 };
    let ours = Node::File { data: b"a\nb\nc\n".to_vec(), mode: 0o644, uid: 0, gid: 0 };
    let theirs = Node::File { data: b"a\nb\n".to_vec(), mode: 0o600, uid: 0, gid: 0 };
    let o = merge(&tree(&[("f", base)]), &tree(&[("f", ours)]), &tree(&[("f", theirs)]));
    assert_eq!(put(&o, "f"), Some(&Node::File { data: b"a\nb\nc\n".to_vec(), mode: 0o600, uid: 0, gid: 0 }));
}

#[test]
fn directories_come_before_and_go_after_their_contents() {
    let dir = Node::Dir { mode: 0o755, uid: 0, gid: 0 };
    let base = tree(&[("gone", dir.clone()), ("gone/x", file("x\n"))]);
    let theirs = tree(&[("new", dir.clone()), ("new/y", file("y\n"))]);
    let o = merge(&base, &base, &theirs);
    let order: Vec<String> = o
        .changes
        .iter()
        .map(|c| match c {
            Change::Put(p, _) => std::format!("put {p}"),
            Change::Remove(p) => std::format!("remove {p}"),
        })
        .collect();
    assert_eq!(order, ["put new", "put new/y", "remove gone/x", "remove gone"]);
}

#[test]
fn a_base_round_trips() {
    let t = tree(&[
        ("d", Node::Dir { mode: 0o750, uid: 0, gid: 10 }),
        ("d/f", Node::File { data: b"x".to_vec(), mode: 0o640, uid: 1000, gid: 10 }),
        ("localtime", Node::Link { target: String::from("/usr/share/zoneinfo/UTC"), uid: 0, gid: 0 }),
    ]);
    assert_eq!(unarchive(&archive("system-1", &t)), Some((String::from("system-1"), t)));
}
