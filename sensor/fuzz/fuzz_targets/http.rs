#![no_main]
//! HTTP request-line / header / URL helpers, including percent-decoding.
use libfuzzer_sys::fuzz_target;
use maltrail_sensor::protocols::http;
use maltrail_sensor::pyre;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    // request_line() takes prebuilt searchers; building them per call is what the real caller
    // avoids, but here the point is only that the parser never panics.
    let crlf = memchr::memmem::Finder::new("\r\n");
    let sp_http = memchr::memmem::Finder::new(" HTTP/");
    let _ = http::request_line(&text, &crlf, &sp_http);
    for name in ["\r\nHost:", "\r\nUser-Agent:", "\r\nContent-Type:"] {
        let _ = http::header_value(&text, name);
    }
    let unquoted = http::unquote(&text);
    let _ = http::splitext(&text);
    let _ = http::urlparse_path_query(&text);
    let param_value = pyre::compile(r"(\w+=)[^&=]+");
    let _ = http::build_checks(&text, Some(&text), &unquoted, &param_value);
});
