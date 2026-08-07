//! HTTP parsing helpers used by the request/response blocks of
//! `sensor.py:_process_packet()`.
//!
//! The Python code works on a single decoded string with `find()` calls rather than a real
//! HTTP parser, and the exact offsets it uses are observable in the emitted trails, so
//! these helpers reproduce that behaviour rather than "improving" it:
//!
//!  * a header value is only extracted when its terminating CRLF is present in the
//!    captured bytes (otherwise Python's `find` returns -1 and the field is skipped),
//!  * header names are matched case-sensitively against `"\r\nHost:"` etc.,
//!  * the FIRST occurrence wins for duplicate headers,
//!  * `%`-decoding follows `urllib.parse.unquote` (UTF-8, `errors="replace"`).

use std::borrow::Cow;

/// `first_index = data.find(name); ... last_index = data.find("\r\n", first_index)`
///
/// `name` must include the leading CRLF, exactly like the Python call sites.
/// Find a header's raw value with a PREBUILT searcher.
///
/// `memmem::find(haystack, needle)` constructs a `Finder` on every call — computing its rare-byte
/// heuristic — and on a 169-byte HTTP payload that construction costs more than the search saves.
/// The searchers for the fixed header names are built once in `Statics`; a callgrind profile put
/// ~8% of the packet path in `FinderBuilder::build_forward_with_ranker` before this change.
pub fn header_value_with<'a>(
    data: &'a str,
    finder: &memchr::memmem::Finder<'_>,
    name_len: usize,
    crlf: &memchr::memmem::Finder<'_>,
) -> Option<&'a str> {
    let first = finder.find(data.as_bytes())? + name_len;
    let rest = &data[first..];
    let end = crlf.find(rest.as_bytes())?;
    if end == 0 {
        return Some("");
    }
    Some(&rest[..end])
}

pub fn header_value<'a>(data: &'a str, name: &str) -> Option<&'a str> {
    let first = data.find(name)? + name.len();
    let rest = &data[first..];
    let end = rest.find("\r\n")?;
    Some(&rest[..end])
}

/// The request line, when the payload carries one (`" HTTP/" in tcp_data`), split exactly
/// like Python: the line must contain exactly two spaces.
pub struct RequestLine<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub version: &'a str,
}

pub fn request_line<'a>(
    data: &'a str,
    crlf: &memchr::memmem::Finder<'_>,
    sp_http: &memchr::memmem::Finder<'_>,
) -> Option<RequestLine<'a>> {
    let end = crlf.find(data.as_bytes())?;
    let line = &data[..end];
    // `line.matches(' ').count()` built a pattern iterator and walked it; that plus the
    // `contains(" HTTP/")` substring search was ~17% of the HTTP path in a callgrind profile.
    // Counting bytes and reusing the prebuilt searcher does the same job.
    //
    // The `" HTTP/"` search deliberately covers the WHOLE line rather than just the last field:
    // Python's test is `line.count(' ') == 2 and " HTTP/" in line`, which accepts a line like
    // `"GET HTTP/1.1 x"` (method `GET`, path `HTTP/1.1`), and that is observable in the trail.
    let bytes = line.as_bytes();
    let mut spaces = 0u32;
    let mut first = 0usize;
    let mut second = 0usize;
    for (i, b) in bytes.iter().enumerate() {
        if *b == b' ' {
            spaces += 1;
            if spaces == 1 {
                first = i;
            } else if spaces == 2 {
                second = i;
            } else {
                return None; // more than two: Python's count check fails
            }
        }
    }
    if spaces != 2 || sp_http.find(bytes).is_none() {
        return None;
    }
    Some(RequestLine { method: &line[..first], path: &line[first + 1..second], version: &line[second + 1..] })
}

/// `urllib.parse.unquote(string, encoding='utf-8', errors='replace')`
///
/// Literal and percent-decoded bytes of one ASCII run are decoded together, so
/// `"a%C3%A9b"` becomes `"aéb"`; a malformed escape (`%zz`, `%4`) stays literal.
/// `urllib.parse.unquote()`. Borrows when there is nothing to decode, which is the common case:
/// most request paths and User-Agents contain no percent-escape at all.
pub fn unquote_cow(value: &str) -> std::borrow::Cow<'_, str> {
    if !value.contains('%') {
        return std::borrow::Cow::Borrowed(value);
    }
    std::borrow::Cow::Owned(unquote(value))
}

pub fn unquote(value: &str) -> String {
    if !value.contains('%') {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    let mut run: Vec<u8> = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0usize;

    let flush = |run: &mut Vec<u8>, out: &mut String| {
        if !run.is_empty() {
            out.push_str(&String::from_utf8_lossy(run));
            run.clear();
        }
    };

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            let hi = bytes.get(i + 1).copied();
            let lo = bytes.get(i + 2).copied();
            match (hi.and_then(hex_val), lo.and_then(hex_val)) {
                (Some(h), Some(l)) => {
                    run.push((h << 4) | l);
                    i += 3;
                    continue;
                }
                _ => {
                    run.push(b'%');
                    i += 1;
                    continue;
                }
            }
        }
        if b < 0x80 {
            run.push(b);
            i += 1;
            continue;
        }
        // A non-ASCII character terminates the ASCII run (urllib splits on ASCII runs).
        flush(&mut run, &mut out);
        let mut end = i + 1;
        while end < bytes.len() && (bytes[end] & 0xc0) == 0x80 {
            end += 1;
        }
        out.push_str(&value[i..end]);
        i = end;
    }
    flush(&mut run, &mut out);
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// `os.path.splitext(filename)` — returns `(name, extension)`.
pub fn splitext(filename: &str) -> (&str, &str) {
    let Some(dot) = filename.rfind('.') else {
        return (filename, "");
    };
    // Leading dots are part of the name (".bashrc" has no extension).
    let mut i = 0usize;
    let bytes = filename.as_bytes();
    while i < dot {
        if bytes[i] != b'.' {
            return (&filename[..dot], &filename[dot..]);
        }
        i += 1;
    }
    (filename, "")
}

/// The `path` / `query` components of `urlparse("http://<url>")`.
pub struct UrlParts<'a> {
    pub path: &'a str,
    pub query: &'a str,
}

pub fn urlparse_path_query(url: &str) -> UrlParts<'_> {
    // url is "host[:port][/path][?query][#fragment]" (the scheme is added by the caller).
    let netloc_end = url.find(['/', '?', '#']).unwrap_or(url.len());
    let rest = &url[netloc_end..];
    let (rest, _fragment) = match rest.find('#') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    match rest.find('?') {
        Some(i) => UrlParts { path: &rest[..i], query: &rest[i + 1..] },
        None => UrlParts { path: rest, query: "" },
    }
}

/// Build the URL-trail candidate list, mirroring the `checks` construction in
/// `sensor.py:_process_packet()` (order matters: the first hit wins).
///
/// Every candidate except the parameter-stripped one is a SLICE of `path`, so they are returned
/// borrowed: this runs on every HTTP request and used to allocate up to six `String`s per packet.
pub fn build_checks<'a>(
    path: &'a str,
    post_data: Option<&str>,
    unquoted_post_data: &str,
    param_value: &regex::Regex,
) -> Vec<Cow<'a, str>> {
    let mut checks: Vec<Cow<'a, str>> = Vec::with_capacity(6);
    checks.push(Cow::Borrowed(path.trim_end_matches('/')));

    if path.contains('?') {
        let base = path.split('?').next().unwrap_or("");
        checks.push(Cow::Borrowed(base.trim_end_matches('/')));

        if let Some(idx) = path.find('=') {
            checks.push(Cow::Borrowed(&path[..idx + 1]));
        }

        // The only candidate that is not a substring of `path`.
        let stripped = param_value.replace_all(path, "$1");
        if !checks.iter().any(|c| c.as_ref() == stripped.as_ref()) {
            let slash_count = stripped.matches('/').count();
            let last_segment = stripped.rsplit('/').next().map(|s| format!("/{s}"));
            checks.push(Cow::Owned(stripped.into_owned()));
            if slash_count > 1 {
                if let Some(last) = last_segment {
                    checks.push(Cow::Owned(last));
                }
            }
        }
    } else if post_data.is_some() {
        checks.push(Cow::Owned(format!("{}?{}", path, unquoted_post_data.to_lowercase())));
    }

    // Python indexes `checks[-1]` and `checks[0]` after the block above; both may be owned, so
    // the slices are taken before pushing to avoid holding a borrow into the vector.
    let last_is_long = checks[checks.len() - 1].matches('/').count() > 1;
    if last_is_long {
        let last = checks[checks.len() - 1].clone();
        if let Some(idx) = last.rfind('/') {
            checks.push(match last {
                Cow::Borrowed(s) => Cow::Borrowed(&s[..idx]),
                Cow::Owned(ref s) => Cow::Owned(s[..idx].to_string()),
            });
        }
        let first = checks[0].clone();
        if let Some(idx) = first.rfind('/') {
            let tail = &first[idx..];
            let cut = tail.split('?').next().unwrap_or(tail);
            checks.push(match first {
                Cow::Borrowed(s) => Cow::Borrowed(&s[idx..idx + cut.len()]),
                Cow::Owned(_) => Cow::Owned(cut.to_string()),
            });
        }
    }

    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_extraction() {
        let data = "GET / HTTP/1.1\r\nHost: evil.com\r\nUser-Agent: curl/8\r\n\r\n";
        assert_eq!(header_value(data, "\r\nHost:"), Some(" evil.com"));
        assert_eq!(header_value(data, "\r\nUser-Agent:"), Some(" curl/8"));
        assert_eq!(header_value(data, "\r\nReferer:"), None);
    }

    #[test]
    fn header_without_terminating_crlf_is_skipped() {
        // a snaplen-truncated request: Python's inner find() returns -1
        let data = "GET / HTTP/1.1\r\nHost: evil.com";
        assert_eq!(header_value(data, "\r\nHost:"), None);
    }

    #[test]
    fn duplicate_headers_take_the_first() {
        let data = "GET / HTTP/1.1\r\nHost: first.com\r\nHost: second.com\r\n\r\n";
        assert_eq!(header_value(data, "\r\nHost:"), Some(" first.com"));
    }

    #[test]
    fn header_matching_is_case_sensitive_like_python() {
        let data = "GET / HTTP/1.1\r\nhost: evil.com\r\n\r\n";
        assert_eq!(header_value(data, "\r\nHost:"), None);
    }

    #[test]
    fn request_line_rules() {
        let r = request_line(
            "GET /x HTTP/1.1\r\nHost: a\r\n\r\n",
            &memchr::memmem::Finder::new("\r\n"),
            &memchr::memmem::Finder::new(" HTTP/"),
        )
        .unwrap();
        assert_eq!((r.method, r.path, r.version), ("GET", "/x", "HTTP/1.1"));
        // three spaces -> Python's `line.count(' ') == 2` guard rejects it
        assert!(request_line(
            "GET /a b HTTP/1.1\r\n",
            &memchr::memmem::Finder::new("\r\n"),
            &memchr::memmem::Finder::new(" HTTP/")
        )
        .is_none());
        assert!(request_line(
            "GET /x\r\n",
            &memchr::memmem::Finder::new("\r\n"),
            &memchr::memmem::Finder::new(" HTTP/")
        )
        .is_none());
        assert!(request_line(
            "no crlf here",
            &memchr::memmem::Finder::new("\r\n"),
            &memchr::memmem::Finder::new(" HTTP/")
        )
        .is_none());
    }

    #[test]
    fn unquote_matches_urllib() {
        assert_eq!(unquote("plain"), "plain");
        assert_eq!(unquote("a%20b"), "a b");
        assert_eq!(unquote("%2e%2e%2f"), "../");
        assert_eq!(unquote("a%C3%A9b"), "aéb");
        // malformed escapes stay literal
        assert_eq!(unquote("100%"), "100%");
        assert_eq!(unquote("%zz"), "%zz");
        assert_eq!(unquote("%4"), "%4");
        assert_eq!(unquote("a%%20b"), "a% b");
        // invalid UTF-8 becomes U+FFFD (errors="replace")
        assert_eq!(unquote("%ff"), "\u{fffd}");
        // non-ASCII passthrough
        assert_eq!(unquote("é%20x"), "é x");
    }

    #[test]
    fn splitext_matches_posixpath() {
        assert_eq!(splitext("setup.exe"), ("setup", ".exe"));
        assert_eq!(splitext("archive.tar.gz"), ("archive.tar", ".gz"));
        assert_eq!(splitext("noext"), ("noext", ""));
        assert_eq!(splitext(".bashrc"), (".bashrc", ""));
        assert_eq!(splitext(""), ("", ""));
        assert_eq!(splitext("..x"), ("..x", ""));
    }

    #[test]
    fn urlparse_components() {
        let u = urlparse_path_query("evil.com/a/b.exe?x=1#frag");
        assert_eq!(u.path, "/a/b.exe");
        assert_eq!(u.query, "x=1");
        let u = urlparse_path_query("evil.com");
        assert_eq!(u.path, "");
        assert_eq!(u.query, "");
        let u = urlparse_path_query("evil.com:8080/x");
        assert_eq!(u.path, "/x");
    }

    fn param_re() -> regex::Regex {
        crate::pyre::compile(r"(\w+=)[^&=]+")
    }

    #[test]
    fn checks_for_a_plain_path() {
        let checks = build_checks("/malicious-login.php", None, "", &param_re());
        assert_eq!(checks, vec!["/malicious-login.php"]);
    }

    #[test]
    fn checks_for_a_query_path() {
        let checks = build_checks("/a/b/c.php?id=1&x=2", None, "", &param_re());
        assert_eq!(
            checks,
            vec!["/a/b/c.php?id=1&x=2", "/a/b/c.php", "/a/b/c.php?id=", "/a/b/c.php?id=&x=", "/c.php?id=&x=",]
        );
    }

    #[test]
    fn checks_for_a_post_body() {
        let checks = build_checks("/submit", Some("q=1"), "q=1", &param_re());
        assert_eq!(checks, vec!["/submit", "/submit?q=1"]);
    }

    #[test]
    fn checks_skip_the_duplicate_stripped_form() {
        // "/a/b/c/d?p=1" -> the parameter-stripped form equals an earlier candidate, so
        // Python does not append it again (nor its "/last" variant).
        let checks = build_checks("/a/b/c/d?p=1", None, "", &param_re());
        assert_eq!(checks, vec!["/a/b/c/d?p=1", "/a/b/c/d", "/a/b/c/d?p=", "/a/b/c", "/d"]);
    }

    #[test]
    fn checks_for_a_root_path() {
        assert_eq!(build_checks("/", None, "", &param_re()), vec![""]);
    }

    #[test]
    fn deep_path_adds_parent_and_tail() {
        let checks = build_checks("/a/b/c", None, "", &param_re());
        assert_eq!(checks, vec!["/a/b/c", "/a/b", "/c"]);
    }
}
