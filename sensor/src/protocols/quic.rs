//! QUIC Initial SNI extraction — a port of `core/quic_sni.py`.
//!
//! The Initial packet's header protection and payload encryption use keys derived from the
//! *public* Destination Connection ID, so a passive sensor can read the ClientHello without
//! any secrets. The AEAD tag is deliberately not verified (Python does not verify it
//! either); only the CTR keystream is needed to recover the plaintext.
//!
//! Bounds and CPU are capped exactly like Python: at most `MAX_INITIAL_DECRYPT` bytes are
//! decrypted per packet, with a 512-byte first attempt (the ClientHello sits at the front
//! of the payload; the rest is PADDING).

use aes::cipher::{BlockEncrypt, KeyInit as _};
use aes::Aes128;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::tls;

/// `core/quic_sni.py:MAX_INITIAL_DECRYPT`
pub const MAX_INITIAL_DECRYPT: usize = 2048;

/// RFC 9001 (QUIC v1) initial salt
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f,
    0x0a,
];
/// RFC 9369 (QUIC v2) initial salt
const INITIAL_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e,
    0xd9,
];

type HmacSha256 = Hmac<Sha256>;

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).expect("hmac accepts any key length");
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

/// Every output this schedule asks for is 32 bytes or fewer, so the buffers live on the stack.
///
/// The general form allocated a Vec for the output, another for the running block, and one more
/// per HMAC round via `to_vec()` - and `hkdf_expand_label` added two more building its info
/// string. Four labels are derived for every QUIC Initial packet, so that was a dozen small
/// allocations on a path that runs per packet. Identical bytes out: the loop is unchanged, it
/// just writes into fixed storage.
const HKDF_MAX: usize = 32;

fn hkdf_expand_into(prk: &[u8], info: &[u8], length: usize, out: &mut [u8; HKDF_MAX]) {
    debug_assert!(length <= HKDF_MAX);
    let mut written = 0usize;
    let mut have_prev = false;
    let mut prev = [0u8; 32];
    let mut counter: u8 = 1;
    while written < length {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(prk).expect("hmac accepts any key length");
        if have_prev {
            mac.update(&prev);
        }
        mac.update(info);
        mac.update(&[counter]);
        prev.copy_from_slice(&mac.finalize().into_bytes());
        have_prev = true;
        let take = (length - written).min(prev.len());
        out[written..written + take].copy_from_slice(&prev[..take]);
        written += take;
        counter = counter.wrapping_add(1);
        if counter == 0 {
            break;
        }
    }
}

fn hkdf_expand_label_into(secret: &[u8], label: &[u8], length: usize) -> [u8; HKDF_MAX] {
    // "tls13 " + label, then the TLS 1.3 HkdfLabel wrapper. Longest label here is "quic hp".
    let mut info = [0u8; 64];
    let mut n = 0usize;
    info[n..n + 2].copy_from_slice(&(length as u16).to_be_bytes());
    n += 2;
    let full_len = 6 + label.len();
    info[n] = full_len as u8;
    n += 1;
    info[n..n + 6].copy_from_slice(b"tls13 ");
    n += 6;
    info[n..n + label.len()].copy_from_slice(label);
    n += label.len();
    info[n] = 0;
    n += 1;
    let mut out = [0u8; HKDF_MAX];
    hkdf_expand_into(secret, &info[..n], length, &mut out);
    out
}

#[cfg(test)]
fn hkdf_expand_label(secret: &[u8], label: &[u8], length: usize) -> Vec<u8> {
    hkdf_expand_label_into(secret, label, length)[..length].to_vec()
}

pub struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

/// `core/quic_sni.py:derive_client_initial_keys()`
pub fn derive_client_initial_keys(dcid: &[u8], version_kind: u8) -> InitialKeys {
    let (salt, klbl, ivlbl, hplbl): (&[u8], &[u8], &[u8], &[u8]) = if version_kind == 2 {
        (&INITIAL_SALT_V2, b"quicv2 key", b"quicv2 iv", b"quicv2 hp")
    } else {
        (&INITIAL_SALT_V1, b"quic key", b"quic iv", b"quic hp")
    };
    let initial_secret = hkdf_extract(salt, dcid);
    let client_secret = hkdf_expand_label_into(&initial_secret, b"client in", 32);
    let key = hkdf_expand_label_into(&client_secret[..32], klbl, 16);
    let iv = hkdf_expand_label_into(&client_secret[..32], ivlbl, 12);
    let hp = hkdf_expand_label_into(&client_secret[..32], hplbl, 16);

    let mut out = InitialKeys { key: [0; 16], iv: [0; 12], hp: [0; 16] };
    out.key.copy_from_slice(&key[..16]);
    out.iv.copy_from_slice(&iv[..12]);
    out.hp.copy_from_slice(&hp[..16]);
    out
}

fn aes_ecb_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(key.into());
    let mut buf = *block;
    cipher.encrypt_block((&mut buf).into());
    buf
}

/// AES-128-CTR with a full 128-bit big-endian counter, matching Python's fallback
/// implementation (and `cryptography`'s CTR mode) bit for bit.
fn aes_ctr_decrypt(key: &[u8; 16], counter0: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(key.into());
    // Written into a sized buffer rather than pushed a byte at a time: a QUIC Initial is around
    // 1,200 bytes, so that was 1,200 Vec pushes - each one a length check and a store - where the
    // work is a 16-byte XOR. Same bytes out, same counter arithmetic.
    let mut out = vec![0u8; data.len()];
    let mut ctr = *counter0;
    for (input, output) in data.chunks(16).zip(out.chunks_mut(16)) {
        let mut ks = ctr;
        cipher.encrypt_block((&mut ks).into());
        for i in 0..input.len() {
            output[i] = input[i] ^ ks[i];
        }
        // 128-bit big-endian increment, exactly as before
        let mut j = 15i32;
        while j >= 0 {
            ctr[j as usize] = ctr[j as usize].wrapping_add(1);
            if ctr[j as usize] != 0 {
                break;
            }
            j -= 1;
        }
    }
    out
}

/// `core/quic_sni.py:_read_varint()`
fn read_varint(buf: &[u8], off: usize) -> Option<(u64, usize)> {
    let b0 = *buf.get(off)?;
    let prefix = b0 >> 6;
    let length = 1usize << prefix;
    let mut val = (b0 & 0x3f) as u64;
    for i in 1..length {
        val = (val << 8) | *buf.get(off + i)? as u64;
    }
    Some((val, off + length))
}

/// `core/quic_sni.py:extract_sni_from_quic_initial()`. Never panics; any malformed or
/// hostile input yields `None`.
pub fn extract_sni_from_quic_initial(udp_payload: &[u8]) -> Option<String> {
    let p = udp_payload;
    if p.len() < 7 {
        return None;
    }
    let first = p[0];
    if first & 0x80 == 0 {
        return None; // not a long header
    }
    let version = u32::from_be_bytes([p[1], p[2], p[3], p[4]]);
    if version == 0 {
        return None; // version negotiation
    }
    let ver_kind: u8 = if version == 0x6b33_43cf { 2 } else { 1 };

    let mut off = 5usize;
    let dcid_len = *p.get(off)? as usize;
    off += 1;
    let dcid = p.get(off..off + dcid_len)?;
    off += dcid_len;
    let scid_len = *p.get(off)? as usize;
    off += 1;
    off = off.checked_add(scid_len)?;

    // long-header packet type must be Initial (v2 remaps it to 0b01)
    if ver_kind == 1 {
        if first & 0x30 != 0x00 {
            return None;
        }
    } else if first & 0x30 != 0x10 {
        return None;
    }

    let (token_len, next) = read_varint(p, off)?;
    off = next.checked_add(token_len as usize)?;
    let (length, next) = read_varint(p, off)?;
    let pn_offset = next;
    let sample_offset = pn_offset.checked_add(4)?;
    if sample_offset.checked_add(16)? > p.len() {
        return None; // too short for the header-protection sample
    }

    let keys = derive_client_initial_keys(dcid, ver_kind);

    let mut sample = [0u8; 16];
    sample.copy_from_slice(p.get(sample_offset..sample_offset + 16)?);
    let mask = aes_ecb_block(&keys.hp, &sample);

    let first_unmasked = first ^ (mask[0] & 0x0f);
    let pn_len = (first_unmasked & 0x03) as usize + 1;
    let pn_bytes = p.get(pn_offset..pn_offset + pn_len)?;
    let mut packet_number: u64 = 0;
    for (i, b) in pn_bytes.iter().enumerate() {
        packet_number = (packet_number << 8) | (b ^ mask[1 + i]) as u64;
    }

    let payload_offset = pn_offset + pn_len;
    let payload_len = (length as usize).checked_sub(pn_len)?;
    let end = payload_offset.saturating_add(payload_len).min(p.len());
    let mut ciphertext = p.get(payload_offset..end)?;
    // the trailing 16 bytes are the (unverified) AEAD tag
    if ciphertext.len() > 16 {
        ciphertext = &ciphertext[..ciphertext.len() - 16];
    }

    // nonce = iv XOR left-padded packet number; the GCM CTR start block is nonce||0x00000002
    let mut nonce = keys.iv;
    let pn_be = packet_number.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn_be[i];
    }
    let mut counter0 = [0u8; 16];
    counter0[..12].copy_from_slice(&nonce);
    counter0[12..].copy_from_slice(&2u32.to_be_bytes());

    let full = ciphertext.len().min(MAX_INITIAL_DECRYPT);
    for cap in [512usize, full] {
        let cap = cap.min(full);
        let plaintext = aes_ctr_decrypt(&keys.key, &counter0, &ciphertext[..cap]);
        if let Some(crypto) = reassemble_crypto(&plaintext) {
            if let Some(sni) = client_hello_sni(&crypto) {
                return Some(sni);
            }
        }
        if cap >= full {
            break;
        }
    }
    None
}

/// `core/quic_sni.py:_reassemble_crypto()` — concatenate CRYPTO frame data by offset.
fn reassemble_crypto(payload: &[u8]) -> Option<Vec<u8>> {
    let mut chunks: std::collections::BTreeMap<u64, Vec<u8>> = std::collections::BTreeMap::new();
    let mut off = 0usize;
    while off < payload.len() {
        let (ftype, next) = read_varint(payload, off)?;
        off = next;
        match ftype {
            0x00 | 0x01 => continue, // PADDING / PING
            0x02 | 0x03 => {
                let (_largest, n) = read_varint(payload, off)?;
                off = n;
                let (_delay, n) = read_varint(payload, off)?;
                off = n;
                let (range_count, n) = read_varint(payload, off)?;
                off = n;
                let (_first, n) = read_varint(payload, off)?;
                off = n;
                // A hostile range_count must not spin: it is bounded by the buffer, since
                // every read_varint consumes at least one byte or fails.
                for _ in 0..range_count {
                    let (_gap, n) = read_varint(payload, off)?;
                    off = n;
                    let (_len, n) = read_varint(payload, off)?;
                    off = n;
                }
                if ftype == 0x03 {
                    for _ in 0..3 {
                        let (_v, n) = read_varint(payload, off)?;
                        off = n;
                    }
                }
                continue;
            }
            0x06 => {
                let (c_off, n) = read_varint(payload, off)?;
                off = n;
                let (c_len, n) = read_varint(payload, off)?;
                off = n;
                let end = off.saturating_add(c_len as usize).min(payload.len());
                chunks.insert(c_off, payload.get(off..end)?.to_vec());
                off = end;
                continue;
            }
            _ => break, // unknown frame: stop
        }
    }
    if chunks.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for (_, chunk) in chunks {
        out.extend_from_slice(&chunk);
    }
    Some(out)
}

/// `core/quic_sni.py:_client_hello_sni()` — note this variant does NOT lower-case the
/// host (it validates case-insensitively instead), unlike the TLS-over-TCP path.
fn client_hello_sni(handshake: &[u8]) -> Option<String> {
    if handshake.len() < 4 || handshake[0] != 0x01 {
        return None;
    }
    let h = handshake;
    let mut pos = 4usize;
    pos += 2 + 32; // legacy_version + random
    if pos >= h.len() {
        return None;
    }
    let sid_len = *h.get(pos)? as usize;
    pos += 1 + sid_len;
    let cs_len = u16::from_be_bytes([*h.get(pos)?, *h.get(pos + 1)?]) as usize;
    pos += 2 + cs_len;
    let comp_len = *h.get(pos)? as usize;
    pos += 1 + comp_len;
    let ext_total = u16::from_be_bytes([*h.get(pos)?, *h.get(pos + 1)?]) as usize;
    pos += 2;
    let end = pos.saturating_add(ext_total);

    while pos + 4 <= end && pos + 4 <= h.len() {
        let etype = u16::from_be_bytes([h[pos], h[pos + 1]]);
        let elen = u16::from_be_bytes([h[pos + 2], h[pos + 3]]) as usize;
        pos += 4;
        if etype == 0x0000 {
            let mut sp = pos + 2; // server_name_list length
            if sp + 3 > h.len() {
                return None;
            }
            let ntype = h[sp];
            sp += 1;
            let nlen = u16::from_be_bytes([h[sp], h[sp + 1]]) as usize;
            sp += 2;
            if ntype == 0x00 && sp + nlen <= h.len() {
                let name = std::str::from_utf8(&h[sp..sp + nlen]).ok()?;
                if !name.is_ascii() {
                    return None;
                }
                return if tls::is_hostname(name, false) { Some(name.to_string()) } else { None };
            }
            return None;
        }
        pos = pos.saturating_add(elen);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a real QUIC v1 Initial carrying a ClientHello with the given SNI, using the
    /// same key schedule the parser uses (so a break in either direction is caught).
    fn build_initial(sni: &str, dcid: &[u8]) -> Vec<u8> {
        let hs = crate::protocols::tls::build_client_hello(sni, false);
        // one CRYPTO frame at offset 0
        let mut frames = vec![0x06, 0x00];
        assert!(hs.len() < 16384);
        frames.extend_from_slice(&(0x4000u16 | hs.len() as u16).to_be_bytes()); // 2-byte varint
        frames.extend_from_slice(&hs);
        // pad to a realistic Initial size
        while frames.len() < 1200 {
            frames.push(0x00);
        }

        let keys = derive_client_initial_keys(dcid, 1);
        let pn: u32 = 0;
        let pn_len = 1usize;
        let payload_len = frames.len() + 16; // + AEAD tag
        let length = (payload_len + pn_len) as u64;

        let mut header = vec![0xc0 | (pn_len as u8 - 1)];
        header.extend_from_slice(&1u32.to_be_bytes()); // version 1
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(0); // scid len
        header.push(0x00); // token length varint = 0
        header.extend_from_slice(&(0x4000u16 | length as u16).to_be_bytes());
        let pn_offset = header.len();
        header.push(pn as u8);

        // encrypt the payload with the CTR keystream
        let mut nonce = keys.iv;
        let pn_be = (pn as u64).to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= pn_be[i];
        }
        let mut counter0 = [0u8; 16];
        counter0[..12].copy_from_slice(&nonce);
        counter0[12..].copy_from_slice(&2u32.to_be_bytes());
        let ciphertext = aes_ctr_decrypt(&keys.key, &counter0, &frames);

        let mut packet = header;
        packet.extend_from_slice(&ciphertext);
        packet.extend_from_slice(&[0xaa; 16]); // unverified tag

        // apply header protection
        let sample_offset = pn_offset + 4;
        let mut sample = [0u8; 16];
        sample.copy_from_slice(&packet[sample_offset..sample_offset + 16]);
        let mask = aes_ecb_block(&keys.hp, &sample);
        packet[0] ^= mask[0] & 0x0f;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[1 + i];
        }
        packet
    }

    #[test]
    fn hkdf_matches_rfc_9001_test_vectors() {
        // RFC 9001 A.1: DCID 0x8394c8f03e515708
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let keys = derive_client_initial_keys(&dcid, 1);
        assert_eq!(
            keys.key.to_vec(),
            vec![0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d]
        );
        assert_eq!(keys.iv.to_vec(), vec![0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c]);
        assert_eq!(
            keys.hp.to_vec(),
            vec![0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2]
        );
    }

    #[test]
    fn aes_ecb_matches_fips_197() {
        // FIPS-197 C.1 AES-128
        let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let pt = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ct = aes_ecb_block(&key, &pt);
        assert_eq!(
            ct.to_vec(),
            vec![0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a]
        );
    }

    #[test]
    fn extracts_sni_from_a_real_initial() {
        let pkt = build_initial("evil.example", &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert_eq!(extract_sni_from_quic_initial(&pkt).as_deref(), Some("evil.example"));
    }

    #[test]
    fn ctr_roundtrips() {
        let key = [7u8; 16];
        let ctr = [3u8; 16];
        let data: Vec<u8> = (0..100u8).collect();
        let enc = aes_ctr_decrypt(&key, &ctr, &data);
        assert_eq!(aes_ctr_decrypt(&key, &ctr, &enc), data);
    }

    #[test]
    fn short_header_and_garbage_return_none() {
        assert_eq!(extract_sni_from_quic_initial(&[]), None);
        assert_eq!(extract_sni_from_quic_initial(&[0x40, 0, 0, 0, 1, 0, 0]), None); // short header
        assert_eq!(extract_sni_from_quic_initial(&[0xc0, 0, 0, 0, 0, 0, 0]), None); // version 0
        for n in 0..64usize {
            let _ = extract_sni_from_quic_initial(&vec![0xc3; n]);
        }
    }

    #[test]
    fn truncated_initial_never_panics() {
        let pkt = build_initial("evil.example", &[0xaa; 8]);
        for n in 0..pkt.len() {
            let _ = extract_sni_from_quic_initial(&pkt[..n]);
        }
    }

    #[test]
    fn hostile_frame_stream_terminates() {
        // a CRYPTO frame claiming a huge length, and ACK frames with a huge range count
        let mut payload = vec![0x06, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        payload.extend_from_slice(&[0x41; 32]);
        let _ = reassemble_crypto(&payload);
        let ack = vec![0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let _ = reassemble_crypto(&ack);
    }
}
