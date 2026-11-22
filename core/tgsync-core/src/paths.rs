// SPDX-License-Identifier: AGPL-3.0-or-later
//! Portable vault paths and conflict-copy names (PROTOCOL.md section 8).

use unicode_normalization::UnicodeNormalization;

use crate::{Error, Result};

pub const INTERNAL_DIR: &str = ".tgsync";
pub const TMP_SUFFIX: &str = ".tgsync-tmp";
pub const MAX_PATH_LEN: usize = 240;

fn err(m: impl Into<String>) -> Error {
    Error::Path(m.into())
}

fn reserved(name: &str) -> bool {
    let u = name.to_uppercase();
    matches!(u.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((u.starts_with("COM") || u.starts_with("LPT")) && u.len() == 4 && matches!(u.as_bytes()[3], b'1'..=b'9'))
}

/// Validate and NFC-normalize a vault-relative `/` path.
pub fn normalize(rel: &str) -> Result<String> {
    let n = rel.chars().count();
    if n == 0 || n > MAX_PATH_LEN {
        return Err(err(format!("bad path length: {:?}", rel.chars().take(40).collect::<String>())));
    }
    let rel: String = rel.nfc().collect();
    let b = rel.as_bytes();
    if rel.starts_with('/') || (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':') {
        return Err(err(format!("absolute path not allowed: {rel:?}")));
    }
    if rel
        .chars()
        .any(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*' | '\\' | '\0'..='\x1f'))
    {
        return Err(err(format!("path has characters that are illegal on some platforms: {rel:?}")));
    }
    let parts: Vec<&str> = rel.split('/').collect();
    for part in &parts {
        if matches!(*part, "" | "." | "..") {
            return Err(err(format!("bad path component in {rel:?}")));
        }
        if part.ends_with('.') || part.ends_with(' ') {
            return Err(err(format!("component ends with dot/space (illegal on Windows): {rel:?}")));
        }
        if reserved(part.split('.').next().unwrap_or("")) {
            return Err(err(format!("reserved Windows name in {rel:?}")));
        }
    }
    // Case-insensitive: on macOS and Windows `.TGSYNC` is the same folder as `.tgsync`.
    let first = parts[0].to_lowercase();
    if first == INTERNAL_DIR || first == ".git" {
        return Err(err(format!("reserved directory: {rel:?}")));
    }
    if rel.to_lowercase().ends_with(TMP_SUFFIX) {
        return Err(err("reserved suffix"));
    }
    Ok(rel)
}

/// Python `posixpath.splitext` on a file name: leading dots do not start an extension.
fn split_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if name[..i].chars().any(|c| c != '.') => name.split_at(i),
        _ => (name, ""),
    }
}

/// `YYYY-MM-DD HHMM` in UTC for unix seconds `ts`.
fn utc_stamp(ts: f64) -> String {
    let secs = ts.floor() as i64;
    let (days, sod) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}{:02}", sod / 3600, sod % 3600 / 60)
}

/// Name of the conflict copy of `path` written by member `author` at `ts`.
/// `tag` is normally `author[:6]`; replay passes `author[:5]` + a digit when that name is taken.
pub fn conflict_name_tagged(path: &str, tag: &str, ts: f64) -> String {
    let (dir, base) = match path.rfind('/') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    };
    let (stem, ext) = split_ext(base);
    let name = format!("{stem} (conflict {tag} {}){ext}", utc_stamp(ts));
    if dir.is_empty() {
        name
    } else {
        format!("{dir}/{name}")
    }
}

pub fn conflict_name(path: &str, author: &str, ts: f64) -> String {
    conflict_name_tagged(path, &author.chars().take(6).collect::<String>(), ts)
}
