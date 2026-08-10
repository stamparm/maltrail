//! The event tuple and its textual renderings, byte-identical to `core/log.py`.

use crate::smallstr::SmallStr;

/// `core/enums.py:TRAIL` (a metaclass that returns the attribute name, so the values are
/// just the identifiers).
pub mod trail_type {
    pub const DNS: &str = "DNS";
    pub const IP: &str = "IP";
    pub const IPORT: &str = "IPORT";
    pub const URL: &str = "URL";
    pub const HTTP: &str = "HTTP";
    pub const UA: &str = "UA";
    pub const PATH: &str = "PATH";
    pub const PORT: &str = "PORT";
    /// TLS server-certificate SHA-1 fingerprint. New in this sensor; see docs/COMPATIBILITY.md.
    pub const CERT: &str = "CERT";
}

/// `core/enums.py:PROTO`
pub mod proto {
    pub const TCP: &str = "TCP";
    pub const UDP: &str = "UDP";
    pub const ICMP: &str = "ICMP";
}

/// An event-tuple field that Python may hold as either an int or a str. The distinction
/// is observable twice: `safe_value(0)` renders `-` (because of `value or '-'`), and
/// `IGNORE_EVENTS_REGEX` is matched against `repr(event_tuple)`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Field {
    Int(i64),
    Text(String),
}

impl Field {
    pub fn dash() -> Field {
        Field::Text("-".to_string())
    }

    pub fn port(value: u16) -> Field {
        Field::Int(value as i64)
    }

    pub fn text(value: impl Into<String>) -> Field {
        Field::Text(value.into())
    }

    /// `str(value)` (before `safe_value`'s `or '-'` fallback).
    pub fn as_plain(&self) -> String {
        match self {
            Field::Int(i) => i.to_string(),
            Field::Text(s) => s.clone(),
        }
    }

    /// Python truthiness, which `safe_value` uses via `value or '-'`.
    fn is_falsy(&self) -> bool {
        match self {
            Field::Int(i) => *i == 0,
            Field::Text(s) => s.is_empty(),
        }
    }

    fn py_repr(&self, out: &mut String) {
        match self {
            Field::Int(i) => out.push_str(&i.to_string()),
            Field::Text(s) => py_repr_str(s, out),
        }
    }
}

impl From<&str> for Field {
    fn from(value: &str) -> Field {
        Field::Text(value.to_string())
    }
}

impl From<String> for Field {
    fn from(value: String) -> Field {
        Field::Text(value)
    }
}

impl From<u16> for Field {
    fn from(value: u16) -> Field {
        Field::Int(value as i64)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub sec: u64,
    pub usec: u32,
    pub src_ip: String,
    pub src_port: Field,
    pub dst_ip: Field,
    pub dst_port: Field,
    pub proto: Field,
    pub trail_type: &'static str,
    pub trail: Field,
    pub info: String,
    pub reference: String,
}

impl Event {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sec: u64,
        usec: u32,
        src_ip: impl Into<String>,
        src_port: impl Into<Field>,
        dst_ip: impl Into<Field>,
        dst_port: impl Into<Field>,
        proto: impl Into<Field>,
        trail_type: &'static str,
        trail: impl Into<Field>,
        info: impl Into<String>,
        reference: impl Into<String>,
    ) -> Event {
        Event {
            sec,
            usec,
            src_ip: src_ip.into(),
            src_port: src_port.into(),
            dst_ip: dst_ip.into(),
            dst_port: dst_port.into(),
            proto: proto.into(),
            trail_type,
            trail: trail.into(),
            info: info.into(),
            reference: reference.into(),
        }
    }

    /// `repr(event_tuple)` as CPython 3 renders it (used only by `IGNORE_EVENTS_REGEX`).
    pub fn py_repr(&self) -> String {
        let mut out = String::with_capacity(160);
        out.push('(');
        out.push_str(&self.sec.to_string());
        out.push_str(", ");
        out.push_str(&self.usec.to_string());
        out.push_str(", ");
        py_repr_str(&self.src_ip, &mut out);
        out.push_str(", ");
        self.src_port.py_repr(&mut out);
        out.push_str(", ");
        self.dst_ip.py_repr(&mut out);
        out.push_str(", ");
        self.dst_port.py_repr(&mut out);
        out.push_str(", ");
        self.proto.py_repr(&mut out);
        out.push_str(", ");
        py_repr_str(self.trail_type, &mut out);
        out.push_str(", ");
        self.trail.py_repr(&mut out);
        out.push_str(", ");
        py_repr_str(&self.info, &mut out);
        out.push_str(", ");
        py_repr_str(&self.reference, &mut out);
        out.push(')');
        out
    }

    /// The event log line, including the trailing newline:
    /// `"<localtime>" <sensor> <src_ip> <src_port> <dst_ip> <dst_port> <proto> <type> <trail> <info> <ref>`
    pub fn render_line(&self, sensor_name: &str, localtime: &str) -> String {
        let mut out = String::with_capacity(224);
        push_safe_value(&mut out, localtime);
        out.push(' ');
        push_safe_value(&mut out, sensor_name);
        out.push(' ');
        push_safe_value(&mut out, &self.src_ip);
        out.push(' ');
        push_safe_field(&mut out, &self.src_port);
        out.push(' ');
        push_safe_field(&mut out, &self.dst_ip);
        out.push(' ');
        push_safe_field(&mut out, &self.dst_port);
        out.push(' ');
        push_safe_field(&mut out, &self.proto);
        out.push(' ');
        push_safe_value(&mut out, self.trail_type);
        out.push(' ');
        push_safe_field(&mut out, &self.trail);
        out.push(' ');
        push_safe_value(&mut out, &self.info);
        out.push(' ');
        push_safe_value(&mut out, &self.reference);
        out.push('\n');
        out
    }
}

/// CPython `repr()` of a `str`: single quotes unless the value contains `'` and no `"`.
pub fn py_repr_str(value: &str, out: &mut String) {
    let quote = if value.contains('\'') && !value.contains('"') { '"' } else { '\'' };
    out.push(quote);
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
}

/// `core/log.py:safe_value()`
pub fn safe_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    push_safe_value(&mut out, value);
    out
}

fn push_safe_field(out: &mut String, field: &Field) {
    if field.is_falsy() {
        out.push('-');
        return;
    }
    match field {
        // Integers can never contain a space, a quote or a newline.
        Field::Int(i) => out.push_str(&i.to_string()),
        Field::Text(s) => push_safe_value(out, s),
    }
}

fn push_safe_value(out: &mut String, value: &str) {
    if value.is_empty() {
        out.push('-');
        return;
    }
    // NOTE: CR/LF are flattened to a space FIRST (core/log.py), so a newline-only value
    // becomes a quoted space rather than splitting the record.
    let needs_flatten = value.bytes().any(|b| b == b'\n' || b == b'\r');
    let flattened: std::borrow::Cow<'_, str> = if needs_flatten {
        std::borrow::Cow::Owned(value.replace(['\n', '\r'], " "))
    } else {
        std::borrow::Cow::Borrowed(value)
    };
    if flattened.contains(' ') || flattened.contains('"') {
        out.push('"');
        for ch in flattened.chars() {
            if ch == '"' {
                out.push_str("\"\"");
            } else {
                out.push(ch);
            }
        }
        out.push('"');
    } else {
        out.push_str(&flattened);
    }
}

/// `"%s.%06d" % (time.strftime(TIME_FORMAT, time.localtime(int(sec))), usec)`
pub fn local_time_string(sec: u64, usec: u32) -> SmallStr<40> {
    let mut out = SmallStr::<40>::new();
    // SAFETY: an all-zero `libc::tm` is a valid value of the type (it is a plain struct of
    // integers and, on glibc, two pointers that localtime_r overwrites before any read).
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t = sec as libc::time_t;
    // SAFETY: `t` is a valid time_t and `tm` is a live, properly aligned tm we own;
    // localtime_r writes into it and never retains the pointer. Used instead of a date
    // crate so the rendering matches Python's time.localtime() (same TZ database, same
    // TZ environment variable handling) exactly.
    let ok = unsafe { !libc::localtime_r(&t, &mut tm).is_null() };
    if !ok {
        out.push_str("1970-01-01 00:00:00.000000");
        return out;
    }
    push_pad4(&mut out, tm.tm_year as i64 + 1900);
    out.push_byte(b'-');
    push_pad2(&mut out, tm.tm_mon as i64 + 1);
    out.push_byte(b'-');
    push_pad2(&mut out, tm.tm_mday as i64);
    out.push_byte(b' ');
    push_pad2(&mut out, tm.tm_hour as i64);
    out.push_byte(b':');
    push_pad2(&mut out, tm.tm_min as i64);
    out.push_byte(b':');
    push_pad2(&mut out, tm.tm_sec as i64);
    out.push_byte(b'.');
    push_pad(&mut out, usec as i64, 6);
    out
}

/// `time.strftime("%Y-%m-%d", time.localtime(sec))` — the daily log file name.
pub fn local_date_string(sec: u64) -> SmallStr<16> {
    let mut out = SmallStr::<16>::new();
    // SAFETY: an all-zero `libc::tm` is a valid value of the type (it is a plain struct of
    // integers and, on glibc, two pointers that localtime_r overwrites before any read).
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t = sec as libc::time_t;
    // SAFETY: see local_time_string().
    if unsafe { libc::localtime_r(&t, &mut tm).is_null() } {
        out.push_str("1970-01-01");
        return out;
    }
    push_pad4(&mut out, tm.tm_year as i64 + 1900);
    out.push_byte(b'-');
    push_pad2(&mut out, tm.tm_mon as i64 + 1);
    out.push_byte(b'-');
    push_pad2(&mut out, tm.tm_mday as i64);
    out
}

/// `time.strftime("%b %d %H:%M:%S", time.localtime(sec))` — the CEF/syslog timestamp.
pub fn syslog_time_string(sec: u64) -> String {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    // SAFETY: an all-zero `libc::tm` is a valid value of the type (it is a plain struct of
    // integers and, on glibc, two pointers that localtime_r overwrites before any read).
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t = sec as libc::time_t;
    // SAFETY: see local_time_string().
    if unsafe { libc::localtime_r(&t, &mut tm).is_null() } {
        return "Jan 01 00:00:00".to_string();
    }
    let mon = MONTHS[(tm.tm_mon as usize).min(11)];
    format!("{} {:02} {:02}:{:02}:{:02}", mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec)
}

fn push_pad<const N: usize>(out: &mut SmallStr<N>, value: i64, width: usize) {
    let text = value.to_string();
    for _ in text.len()..width {
        out.push_byte(b'0');
    }
    out.push_str(&text);
}

fn push_pad2<const N: usize>(out: &mut SmallStr<N>, value: i64) {
    push_pad(out, value, 2);
}

fn push_pad4<const N: usize>(out: &mut SmallStr<N>, value: i64) {
    push_pad(out, value, 4);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_value_doctests() {
        // core/log.py:safe_value docstring
        assert_eq!(safe_value("hello"), "hello");
        assert_eq!(safe_value(""), "-");
        assert_eq!(safe_value("a b"), "\"a b\"");
        assert_eq!(safe_value("a\"b"), "\"a\"\"b\"");
        assert_eq!(safe_value("line\nbreak"), "\"line break\"");
    }

    #[test]
    fn safe_value_newline_only_is_quoted_space() {
        assert_eq!(safe_value("\n"), "\" \"");
        assert_eq!(safe_value("\r\n"), "\"  \"");
    }

    #[test]
    fn falsy_fields_render_dash() {
        // safe_value(value or '-'): a zero port and an empty string both become '-'
        let mut out = String::new();
        push_safe_field(&mut out, &Field::Int(0));
        assert_eq!(out, "-");
        out.clear();
        push_safe_field(&mut out, &Field::Text(String::new()));
        assert_eq!(out, "-");
        out.clear();
        push_safe_field(&mut out, &Field::Int(443));
        assert_eq!(out, "443");
    }

    fn sample() -> Event {
        Event::new(
            1700000000,
            123456,
            "10.0.0.5",
            50000u16,
            "66.66.66.66",
            443u16,
            proto::TCP,
            trail_type::IP,
            "66.66.66.66",
            "malware (test)",
            "(static)",
        )
    }

    #[test]
    fn event_line_layout() {
        let e = sample();
        let line = e.render_line("sensor1", "2023-11-14 22:13:20.123456");
        assert_eq!(
            line,
            "\"2023-11-14 22:13:20.123456\" sensor1 10.0.0.5 50000 66.66.66.66 443 TCP IP 66.66.66.66 \"malware (test)\" (static)\n"
        );
    }

    #[test]
    fn icmp_dash_ports() {
        let e = Event::new(
            1,
            0,
            "10.0.0.5",
            Field::dash(),
            "66.66.66.66",
            Field::dash(),
            proto::ICMP,
            trail_type::IP,
            "66.66.66.66",
            "badnet",
            "ref",
        );
        let line = e.render_line("s", "2023-11-14 22:13:20.000000");
        assert!(line.contains(" 10.0.0.5 - 66.66.66.66 - ICMP IP "), "{line}");
    }

    #[test]
    fn py_repr_matches_cpython() {
        // repr() of the tuple, as core/ignore.py sees it
        let e = sample();
        assert_eq!(
            e.py_repr(),
            "(1700000000, 123456, '10.0.0.5', 50000, '66.66.66.66', 443, 'TCP', 'IP', '66.66.66.66', 'malware (test)', '(static)')"
        );
    }

    #[test]
    fn py_repr_quoting_rules() {
        let mut out = String::new();
        py_repr_str("it's", &mut out);
        assert_eq!(out, "\"it's\"");
        out.clear();
        py_repr_str("a\"b", &mut out);
        assert_eq!(out, "'a\"b'");
        out.clear();
        py_repr_str("a'b\"c", &mut out);
        assert_eq!(out, "'a\\'b\"c'");
        out.clear();
        py_repr_str("tab\there", &mut out);
        assert_eq!(out, "'tab\\there'");
    }

    #[test]
    fn timestamp_rendering() {
        // 0 is rendered in the local timezone; only the shape is asserted here (the exact
        // value depends on TZ, which is exactly what we want to inherit from libc).
        let s = local_time_string(1700000000, 7);
        let text = s.as_str();
        assert_eq!(text.len(), "2023-11-14 22:13:20.000007".len(), "{text}");
        assert!(text.ends_with(".000007"), "{text}");
        assert_eq!(&text[4..5], "-");
        let d = local_date_string(1700000000);
        assert_eq!(d.as_str().len(), 10);
        assert_eq!(&text[..10], d.as_str());
    }
}
