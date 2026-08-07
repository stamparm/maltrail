//! Fixed-capacity stack string, so the hot path can render an IP / `addr:port` key
//! without touching the allocator. Writes past the capacity are truncated rather
//! than panicking (a sensor must never die on formatting).

use std::fmt::Write as _;

#[derive(Clone, Copy)]
pub struct SmallStr<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> SmallStr<N> {
    #[inline]
    pub fn new() -> Self {
        SmallStr { buf: [0u8; N], len: 0 }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        // Only ASCII/UTF-8 fragments are ever pushed (see push_str/push_u*).
        debug_assert!(std::str::from_utf8(&self.buf[..self.len]).is_ok());
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn push_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let n = bytes.len().min(N - self.len);
        // Truncating mid-codepoint would break as_str(); only push whole ASCII here.
        let n = if n == bytes.len() { n } else { floor_char_boundary(bytes, n) };
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    #[inline]
    pub fn push_byte(&mut self, b: u8) {
        debug_assert!(b.is_ascii());
        if self.len < N {
            self.buf[self.len] = b;
            self.len += 1;
        }
    }

    #[inline]
    pub fn push_u16(&mut self, v: u16) {
        let mut tmp = [0u8; 5];
        let mut i = tmp.len();
        let mut v = v;
        loop {
            i -= 1;
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        for &b in &tmp[i..] {
            self.push_byte(b);
        }
    }

    #[inline]
    pub fn push_u8_dec(&mut self, v: u8) {
        self.push_u16(v as u16);
    }
}

impl<const N: usize> Default for SmallStr<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> std::fmt::Write for SmallStr<N> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.push_str(s);
        Ok(())
    }
}

impl<const N: usize> std::fmt::Display for SmallStr<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<const N: usize> std::fmt::Debug for SmallStr<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_str(), f)
    }
}

fn floor_char_boundary(bytes: &[u8], mut n: usize) -> usize {
    while n > 0 && (bytes[n] & 0xc0) == 0x80 {
        n -= 1;
    }
    n
}

/// Convenience: format into a fresh SmallStr, ignoring overflow.
pub fn fmt_small<const N: usize>(args: std::fmt::Arguments<'_>) -> SmallStr<N> {
    let mut s = SmallStr::<N>::new();
    let _ = s.write_fmt(args);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_truncate() {
        let mut s = SmallStr::<8>::new();
        s.push_str("abc");
        s.push_u16(1234);
        assert_eq!(s.as_str(), "abc1234");
        s.push_str("XYZ");
        assert_eq!(s.as_str(), "abc1234X");
    }

    #[test]
    fn numbers() {
        let mut s = SmallStr::<16>::new();
        s.push_u16(0);
        s.push_byte(b'.');
        s.push_u16(65535);
        assert_eq!(s.as_str(), "0.65535");
    }
}
