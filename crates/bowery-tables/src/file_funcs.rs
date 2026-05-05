//! Phase-9 final-7 (slice 2b): scalar SQL functions for
//! per-path file inspection + hashing.
//!
//! The original slice-2b plan was a `file` table requiring a
//! vtab `WHERE path = '…'` filter pushdown. That's a lot of
//! rusqlite-vtab boilerplate for a constraint that's much more
//! cleanly expressed at the operator's call site:
//!
//! ```sql
//! -- old plan (vtab):
//! SELECT * FROM file WHERE path = '/etc/passwd';
//!
//! -- shipped:
//! SELECT bowery_file_size('/etc/passwd'),
//!        bowery_file_sha256_hex('/etc/passwd');
//! ```
//!
//! Each function takes a single TEXT path argument and returns
//! a scalar value (or NULL on permission denied / not-a-regular-
//! file). They CANNOT enumerate the filesystem — the operator
//! must supply the path. Combined with the per-query timeout +
//! row cap, this means a malicious operator can't trigger an
//! unbounded directory walk via SQL.
//!
//! ## Functions
//!
//! - `bowery_file_exists(path)`        → INTEGER 0/1
//! - `bowery_file_size(path)`          → INTEGER bytes (NULL on stat fail)
//! - `bowery_file_mode(path)`          → INTEGER (raw `st_mode`)
//! - `bowery_file_mtime_unix(path)`    → INTEGER seconds since epoch
//! - `bowery_file_owner_uid(path)`     → INTEGER
//! - `bowery_file_owner_gid(path)`     → INTEGER
//! - `bowery_file_sha256_hex(path)`    → TEXT 64-char hex (NULL on read fail)
//!
//! Hash function caps the read at [`MAX_HASH_BYTES`] to bound
//! per-call memory + time. Files larger than the cap return NULL
//! rather than a partial-content hash; operators wanting partial
//! hashes can chunk client-side.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rusqlite::Connection;
use rusqlite::functions::FunctionFlags;
use sha2::{Digest, Sha256};

use crate::TableError;

/// Maximum bytes hashed by `bowery_file_sha256_hex`. 16 MiB is
/// well above any sensible binary integrity check and keeps
/// per-call latency bounded.
pub const MAX_HASH_BYTES: u64 = 16 * 1024 * 1024;

/// Register every Phase-9 final-7 file function on `conn`.
/// Called from `bowery-sql::register_all` (via the agent's
/// extra-tables wiring) so the functions are available alongside
/// the rest of the surface.
pub fn register_file_functions(conn: &Connection) -> Result<(), TableError> {
    let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DIRECTONLY;

    conn.create_scalar_function("bowery_file_exists", 1, flags, |ctx| {
        let path: String = ctx.get(0)?;
        Ok(i64::from(Path::new(&path).exists()))
    })
    .map_err(TableError::Sqlite)?;

    conn.create_scalar_function("bowery_file_size", 1, flags, |ctx| {
        let path: String = ctx.get(0)?;
        Ok(metadata(&path).and_then(|m| i64::try_from(m.size()).ok()))
    })
    .map_err(TableError::Sqlite)?;

    conn.create_scalar_function("bowery_file_mode", 1, flags, |ctx| {
        let path: String = ctx.get(0)?;
        Ok(metadata(&path).map(|m| i64::from(m.mode())))
    })
    .map_err(TableError::Sqlite)?;

    conn.create_scalar_function("bowery_file_mtime_unix", 1, flags, |ctx| {
        let path: String = ctx.get(0)?;
        Ok(metadata(&path).map(|m| m.mtime()))
    })
    .map_err(TableError::Sqlite)?;

    conn.create_scalar_function("bowery_file_owner_uid", 1, flags, |ctx| {
        let path: String = ctx.get(0)?;
        Ok(metadata(&path).map(|m| i64::from(m.uid())))
    })
    .map_err(TableError::Sqlite)?;

    conn.create_scalar_function("bowery_file_owner_gid", 1, flags, |ctx| {
        let path: String = ctx.get(0)?;
        Ok(metadata(&path).map(|m| i64::from(m.gid())))
    })
    .map_err(TableError::Sqlite)?;

    conn.create_scalar_function("bowery_file_sha256_hex", 1, flags, |ctx| {
        let path: String = ctx.get(0)?;
        Ok(sha256_hex(&path))
    })
    .map_err(TableError::Sqlite)?;

    Ok(())
}

fn metadata(path: &str) -> Option<std::fs::Metadata> {
    std::fs::metadata(path).ok()
}

/// SHA-256 of `path`'s contents as a 64-char lowercase hex
/// string. Returns `None` on stat failure, on non-regular files
/// (avoid hashing pipes / devices / sockets), on read failure,
/// or when the file exceeds `MAX_HASH_BYTES`.
fn sha256_hex(path: &str) -> Option<String> {
    use std::io::Read;

    let meta = metadata(path)?;
    if !meta.is_file() {
        return None;
    }
    if meta.size() > MAX_HASH_BYTES {
        return None;
    }
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        register_file_functions(&conn).unwrap();
        conn
    }

    #[test]
    fn exists_resolves_for_a_known_file() {
        let conn = fresh_conn();
        let exists: i64 = conn
            .query_row(
                "SELECT bowery_file_exists('/etc/passwd')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1);
        let missing: i64 = conn
            .query_row(
                "SELECT bowery_file_exists('/nonexistent/path/x')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(missing, 0);
    }

    #[test]
    fn size_returns_positive_for_known_file() {
        let conn = fresh_conn();
        let size: Option<i64> = conn
            .query_row("SELECT bowery_file_size('/etc/passwd')", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(size.unwrap() > 0);
    }

    #[test]
    fn sha256_hash_round_trips() {
        // Hash a file we can control: a temp file with known
        // contents.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("bowery-test-{}", std::process::id()));
        std::fs::write(&path, b"hello\n").unwrap();
        let conn = fresh_conn();
        let hash: Option<String> = conn
            .query_row(
                "SELECT bowery_file_sha256_hex(?1)",
                [path.to_str().unwrap()],
                |row| row.get(0),
            )
            .unwrap();
        // sha256("hello\n") = 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
        assert_eq!(
            hash.as_deref(),
            Some("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03")
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn sha256_returns_null_for_directory() {
        let conn = fresh_conn();
        let hash: Option<String> = conn
            .query_row("SELECT bowery_file_sha256_hex('/etc')", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(hash.is_none(), "directories should not be hashed");
    }

    #[test]
    fn missing_file_size_returns_null() {
        let conn = fresh_conn();
        let size: Option<i64> = conn
            .query_row(
                "SELECT bowery_file_size('/no/such/file')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(size.is_none());
    }
}
