//! VFun API response bodies. Placeholder `{}` until the client's parser for each
//! endpoint is recovered with REA (see docs/re-log.md).

pub fn respond(request_line: &str, _raw: &str) -> String {
    let _ = request_line;
    "{}".to_string()
}
