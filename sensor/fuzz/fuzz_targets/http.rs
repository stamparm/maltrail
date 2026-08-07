#![no_main]
//! HTTP request-line / header / URL helpers, including percent-decoding.
use libfuzzer_sys::fuzz_target;
use maltrail_sensor::protocols::http;
use maltrail_sensor::pyre;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = http::request_line(&text);
    for name in ["\r\nHost:", "\r\nUser-Agent:", "\r\nContent-Type:"] {
        let _ = http::header_value(&text, name);
    }
    let unquoted = http::unquote(&text);
    let _ = http::splitext(&text);
    let _ = http::urlparse_path_query(&text);
    let param_value = pyre::compile(r"(\w+=)[^&=]+");
    let _ = http::build_checks(&text, Some(&text), &unquoted, &param_value);
});
