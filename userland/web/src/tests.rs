// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn fetch_urls() {
    use crate::http::{Url, UrlError, request};
    let u = Url::parse("http://10.0.2.2:8080/a/b?q=1#frag").unwrap();
    assert_eq!((u.host.as_str(), u.port, u.target.as_str()), ("10.0.2.2", 8080, "/a/b?q=1"));
    let u6 = Url::parse("HTTP://[fec0::2]:81").unwrap();
    assert_eq!((u6.host.as_str(), u6.port, u6.target.as_str()), ("fec0::2", 81, "/"));
    assert_eq!(u6.authority(), "[fec0::2]:81");
    assert_eq!(Url::parse("http://example.com?x").unwrap().target, "/?x");
    let s = Url::parse("https://example.com/x").unwrap();
    assert_eq!(
        (s.https, s.port, s.authority(), s.text()),
        (true, 443, "example.com".into(), "https://example.com/x".into())
    );
    assert_eq!(Url::parse("ftp://example.com/"), Err(UrlError::Scheme));
    for bad in ["example.com", "http://", "http://u@h/", "http://h:0/", "http://h:x/", "http://h/a b"] {
        assert_eq!(Url::parse(bad), Err(UrlError::Bad), "{bad}");
    }
    assert_eq!(u.join("/c").unwrap().text(), "http://10.0.2.2:8080/c");
    assert_eq!(u.join("c?d").unwrap().text(), "http://10.0.2.2:8080/a/c?d");
    assert_eq!(u.join("//other/x").unwrap().text(), "http://other/x");
    assert_eq!(u.join("http://h2:9/y").unwrap().text(), "http://h2:9/y");
    assert!(u.join("https://h2/y").unwrap().https);
    assert_eq!(s.join("//h3/z").unwrap().text(), "https://h3/z");
    let r = std::string::String::from_utf8(request(&u6, "slate-fetch/0.1", 0)).unwrap();
    assert!(r.starts_with("GET / HTTP/1.1\r\nHost: [fec0::2]:81\r\n"), "{r}");
    assert!(r.ends_with("Connection: close\r\n\r\n"));
    assert!(!r.contains("Range"));
    let r = std::string::String::from_utf8(request(&u6, "slate-fetch/0.1", 4096)).unwrap();
    assert!(r.contains("\r\nRange: bytes=4096-\r\n"), "{r}");
}

#[test]
fn fetch_heads_and_chunks() {
    use crate::http::{Chunked, parse_head};
    let raw = b"HTTP/1.1 302 Found\r\nlocation: /next\r\nContent-Length: 0\r\n\r\nrest";
    let (h, used) = parse_head(raw).unwrap().unwrap();
    assert_eq!((h.status, h.reason.as_str(), h.get("Location"), h.length()), (302, "Found", Some("/next"), Some(0)));
    assert_eq!(&raw[used..], b"rest");
    assert_eq!(parse_head(b"HTTP/1.1 200 OK\r\nA: b\r\n"), Ok(None));
    assert!(parse_head(b"SSH-2.0-x\r\n\r\n").is_err());
    let (h, _) = parse_head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n").unwrap().unwrap();
    assert!(h.chunked());
    // A chunked body fed a byte at a time and all at once.
    let body = b"5;ext=1\r\nhello\r\n1\r\n \r\nB\r\nchunked fun\r\n0\r\nTrailer: x\r\n\r\n";
    for step in [1, body.len()] {
        let mut c = Chunked::default();
        let mut got = std::vec::Vec::new();
        let mut done = false;
        for part in body.chunks(step) {
            assert!(!done);
            done = c.feed(part, &mut |b| got.extend_from_slice(b)).unwrap();
        }
        assert!(done);
        assert_eq!(got, b"hello chunked fun");
    }
    assert!(Chunked::default().feed(b"zz\r\n", &mut |_| {}).is_err());
    assert!(Chunked::default().feed(b"1\r\nab\r\n", &mut |_| {}).is_err());
}
