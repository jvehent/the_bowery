//! Shared utmp/wtmp parser used by `logged_in_users` and `last`.
//!
//! The kernel-/glibc-level record layout (`struct utmp` in
//! `<utmp.h>`) is stable across modern Linux: 384 bytes on every
//! `__WORDSIZE`. Files are concatenations of these records with no
//! framing or magic — all framing is implicit in the fixed size.
//!
//! Field layout (offsets in bytes, little-endian on every Linux
//! arch we target):
//!
//! ```text
//!   0..2     ut_type   short
//!   2..4     padding
//!   4..8     ut_pid    pid_t (i32)
//!   8..40    ut_line   char[32]
//!  40..44    ut_id     char[4]
//!  44..76    ut_user   char[32]
//!  76..332   ut_host   char[256]
//! 332..336   ut_exit   { e_termination: i16, e_exit: i16 }
//! 336..340   ut_session i32
//! 340..344   ut_tv.sec  i32
//! 344..348   ut_tv.usec i32
//! 348..364   ut_addr_v6 i32[4]
//! 364..384   __unused
//! ```
//!
//! `tv_sec` overflows in 2038. utmp is an old format. Bowery
//! surfaces the seconds field directly as `i64` (sign-extended) so
//! operators can `WHERE login_time > ...` without us patching over
//! a known kernel-format weakness.

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UtmpRecord {
    pub ut_type: u16,
    pub pid: i32,
    pub line: String,
    pub id: String,
    pub user: String,
    pub host: String,
    pub time_unix: i64,
}

/// Standard utmp record size on Linux (`x86_64` and other 64-bit
/// arches; 32-bit Linux also uses this layout). Held constant
/// since glibc 2.0.
pub(crate) const UTMP_RECORD_SIZE: usize = 384;

/// `USER_PROCESS` `ut_type` — the only value `logged_in_users`
/// surfaces. Other types (`BOOT_TIME=2`, `DEAD_PROCESS=8`,
/// `RUN_LVL=1`, ...) are kept verbatim in the `last` table's
/// `type` column so operators can filter them numerically.
pub(crate) const USER_PROCESS: u16 = 7;

/// Parse a utmp/wtmp byte stream into records. Trailing partial
/// records (i.e. file size not a multiple of 384) are dropped.
pub(crate) fn parse(bytes: &[u8]) -> Vec<UtmpRecord> {
    let mut out = Vec::with_capacity(bytes.len() / UTMP_RECORD_SIZE);
    for chunk in bytes.chunks_exact(UTMP_RECORD_SIZE) {
        if let Some(rec) = parse_one(chunk) {
            out.push(rec);
        }
    }
    out
}

fn parse_one(chunk: &[u8]) -> Option<UtmpRecord> {
    if chunk.len() != UTMP_RECORD_SIZE {
        return None;
    }
    let ut_type = u16::from_le_bytes(chunk[0..2].try_into().ok()?);
    let pid = i32::from_le_bytes(chunk[4..8].try_into().ok()?);
    let line = read_cstr(&chunk[8..40]);
    let id = read_cstr(&chunk[40..44]);
    let user = read_cstr(&chunk[44..76]);
    let host = read_cstr(&chunk[76..332]);
    let tv_sec = i32::from_le_bytes(chunk[340..344].try_into().ok()?);
    Some(UtmpRecord {
        ut_type,
        pid,
        line,
        id,
        user,
        host,
        time_unix: i64::from(tv_sec),
    })
}

/// Decode a NUL-terminated, fixed-width C string from a record
/// field. Trailing NULs / garbage past the first NUL are dropped.
fn read_cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(ut_type: u16, user: &str, line: &str, host: &str, time: i32) -> Vec<u8> {
        let mut buf = vec![0u8; UTMP_RECORD_SIZE];
        buf[0..2].copy_from_slice(&ut_type.to_le_bytes());
        buf[4..8].copy_from_slice(&12345_i32.to_le_bytes());
        let line_bytes = line.as_bytes();
        let len = line_bytes.len().min(31);
        buf[8..8 + len].copy_from_slice(&line_bytes[..len]);
        let user_bytes = user.as_bytes();
        let len = user_bytes.len().min(31);
        buf[44..44 + len].copy_from_slice(&user_bytes[..len]);
        let host_bytes = host.as_bytes();
        let len = host_bytes.len().min(255);
        buf[76..76 + len].copy_from_slice(&host_bytes[..len]);
        buf[340..344].copy_from_slice(&time.to_le_bytes());
        buf
    }

    #[test]
    fn parses_synthesized_records() {
        let mut all = Vec::new();
        all.extend(make_record(
            USER_PROCESS,
            "alice",
            "pts/0",
            "10.0.0.5",
            1_700_000_000,
        ));
        // ut_type=8 is DEAD_PROCESS; we use the literal here to keep
        // the parser test independent of the named constants.
        all.extend(make_record(8, "bob", "pts/1", "", 1_700_000_500));
        let recs = parse(&all);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].ut_type, USER_PROCESS);
        assert_eq!(recs[0].user, "alice");
        assert_eq!(recs[0].line, "pts/0");
        assert_eq!(recs[0].host, "10.0.0.5");
        assert_eq!(recs[0].time_unix, 1_700_000_000);
        assert_eq!(recs[1].ut_type, 8);
    }

    #[test]
    fn rejects_short_trailer() {
        let mut buf = make_record(USER_PROCESS, "x", "tty1", "h", 1);
        buf.extend_from_slice(&[0u8; 100]); // not a full record
        let recs = parse(&buf);
        assert_eq!(recs.len(), 1);
    }
}
