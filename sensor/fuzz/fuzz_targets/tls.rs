#![no_main]
//! TLS ClientHello SNI extraction.
use libfuzzer_sys::fuzz_target;
use maltrail_sensor::protocols::tls;

fuzz_target!(|data: &[u8]| {
    let _ = tls::client_hello_sni(data);
    let _ = tls::parse_sni_extension(data, true);
    let _ = tls::parse_sni_extension(data, false);
});
