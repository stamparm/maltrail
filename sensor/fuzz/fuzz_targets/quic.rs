#![no_main]
//! QUIC Initial header unprotection + CRYPTO frame reassembly + SNI extraction.
use libfuzzer_sys::fuzz_target;
use maltrail_sensor::protocols::quic;

fuzz_target!(|data: &[u8]| {
    let _ = quic::extract_sni_from_quic_initial(data);
});
