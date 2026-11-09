// httparse's Response (third_party/httparse, v1.10.1, fetched by scripts/fetch-thirdparty.sh) behind
// picohttpparser's phr_parse_response signature: the response-side counterpart of httparse_shim.rs.
extern crate httparse;
use std::os::raw::{c_char, c_int};

#[repr(C)]
pub struct PhrHeader { name: *const c_char, name_len: usize, value: *const c_char, value_len: usize }

unsafe fn parse(cfg: &httparse::ParserConfig, buf: *const c_char, len: usize, minor: *mut c_int, status: *mut c_int,
    msg: *mut *const c_char, msg_len: *mut usize, headers: *mut PhrHeader, num_headers: *mut usize) -> c_int {
    let slice = std::slice::from_raw_parts(buf as *const u8, len);
    let mut h = [httparse::EMPTY_HEADER; 100];
    let max = (*num_headers).min(100);
    let mut res = httparse::Response::new(&mut h[..max]);
    match cfg.parse_response(&mut res, slice) {
        Ok(httparse::Status::Complete(n)) => {
            *minor = res.version.unwrap() as c_int;
            *status = res.code.unwrap() as c_int;
            let r = res.reason.unwrap_or("");
            *msg = if r.is_empty() { std::ptr::null() } else { r.as_ptr() as *const c_char };
            *msg_len = r.len();
            for (i, x) in res.headers.iter().enumerate() {
                let o = &mut *headers.add(i);
                o.name = x.name.as_ptr() as *const c_char; o.name_len = x.name.len();
                o.value = x.value.as_ptr() as *const c_char; o.value_len = x.value.len();
            }
            *num_headers = res.headers.len();
            n as c_int
        }
        Ok(httparse::Status::Partial) => -2,
        Err(_) => -1,
    }
}

/// httparse's defaults. Returns bytes consumed, -1 invalid, -2 incomplete (as pico); msg is NULL when the reason is empty.
#[no_mangle]
pub unsafe extern "C" fn hx_parse_response(buf: *const c_char, len: usize, minor: *mut c_int, status: *mut c_int,
    msg: *mut *const c_char, msg_len: *mut usize, headers: *mut PhrHeader, num_headers: *mut usize,
    _last_len: usize) -> c_int {
    parse(&httparse::ParserConfig::default(), buf, len, minor, status, msg, msg_len, headers, num_headers)
}

/// every response leniency httparse has: obs-fold, spaces after a name, several spaces in the status line.
#[no_mangle]
pub unsafe extern "C" fn hx_parse_response_lenient(buf: *const c_char, len: usize, minor: *mut c_int,
    status: *mut c_int, msg: *mut *const c_char, msg_len: *mut usize, headers: *mut PhrHeader,
    num_headers: *mut usize, _last_len: usize) -> c_int {
    let mut cfg = httparse::ParserConfig::default();
    cfg.allow_obsolete_multiline_headers_in_responses(true)
        .allow_spaces_after_header_name_in_responses(true)
        .allow_multiple_spaces_in_response_status_delimiters(true);
    parse(&cfg, buf, len, minor, status, msg, msg_len, headers, num_headers)
}
