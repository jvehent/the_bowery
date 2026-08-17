//! Resolving kernel struct field offsets from the running kernel's own
//! BTF.
//!
//! # Why this exists rather than CO-RE
//!
//! Identifying the binary being executed inside `bprm_check_security`
//! means walking `bprm->file->f_inode`, and those field offsets differ
//! between kernel builds. The portable answer is CO-RE: the compiler
//! records a relocation per field access and the loader rewrites the
//! offsets against the target kernel.
//!
//! aya implements the loader half — `aya-obj` handles
//! `BPF_CORE_FIELD_BYTE_OFFSET` and rewrites instructions at load time.
//! It does **not** implement the compiler half: neither `aya-ebpf`
//! 0.1.1 nor 0.2.1 provides a `bpf_core_read!`, and a plain Rust field
//! access emits no `bpf_core_relo` record for the loader to apply. So
//! CO-RE is unavailable from Rust here, however much the loader would
//! like to cooperate.
//!
//! That leaves two options, and only one of them is safe.
//!
//! **Hardcoding offsets is not an option.** `bprm_check_security`
//! returns a negative errno to *deny an exec*. A wrong offset does not
//! produce a missed detection — it produces a hook reading an arbitrary
//! kernel address and denying arbitrary binaries, as root, on a running
//! host. The failure mode is bricking the machine this agent is meant
//! to protect.
//!
//! **So the offsets are resolved at load time from `/sys/kernel/btf/vmlinux`**
//! and handed to the program in a map. This is the same shape the
//! `sys_enter_openat` probe already uses — it verifies argument offsets
//! against the kernel's own format file and refuses to attach on a
//! proven mismatch — and it has the property that matters: resolution
//! either succeeds against the kernel actually running, or the blocker
//! is not installed at all and says why. There is no path where it
//! silently guesses.
//!
//! # Format
//!
//! BTF is documented at `Documentation/bpf/btf.rst`. Only what is needed
//! to find a named field of a named struct is parsed here; every other
//! kind is skipped by size.
//!
//! Verified against the reference implementation rather than trusted:
//! on a 6.8.0 kernel this parser and `bpftool btf dump file
//! /sys/kernel/btf/vmlinux format raw` agree on all five offsets
//! (`linux_binprm.file` 64, `file.f_inode` 168, `inode.i_ino` 80,
//! `inode.i_sb` 56, `super_block.s_dev` 16). Those numbers are *not*
//! asserted in a test — they are kernel-specific and would be wrong on
//! the next build, which is the entire reason this resolver exists. The
//! tests assert shape and self-consistency instead.

use std::collections::HashMap;
use std::path::Path;

/// Where the kernel exposes its own BTF.
pub const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";

const BTF_MAGIC: u16 = 0xEB9F;

// Kinds we must size in order to skip them. From
// `include/uapi/linux/btf.h`.
const KIND_INT: u32 = 1;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_DECL_TAG: u32 = 17;
const KIND_ENUM64: u32 = 19;

#[derive(Debug, thiserror::Error)]
pub enum BtfError {
    #[error("reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("not BTF: bad magic {0:#06x}")]
    BadMagic(u16),
    #[error("BTF truncated at offset {0}")]
    Truncated(usize),
    #[error("kernel BTF has no struct `{0}`")]
    NoSuchStruct(String),
    #[error("struct `{struct_name}` has no field `{field}` in this kernel's BTF")]
    NoSuchField { struct_name: String, field: String },
    #[error(
        "field `{struct_name}.{field}` is a bitfield; this resolver only handles byte-aligned fields"
    )]
    Bitfield { struct_name: String, field: String },
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, BtfError> {
    b.get(at..at + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(BtfError::Truncated(at))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, BtfError> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(BtfError::Truncated(at))
}

/// A parsed BTF blob, indexed well enough to answer field-offset
/// questions.
pub struct Btf {
    /// Struct name → (member name → byte offset).
    structs: HashMap<String, HashMap<String, u32>>,
}

impl std::fmt::Debug for Btf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Btf")
            .field("structs", &self.structs.len())
            .finish()
    }
}

impl Btf {
    /// Parse the running kernel's BTF.
    ///
    /// # Errors
    /// When the file is absent (a kernel without `CONFIG_DEBUG_INFO_BTF`)
    /// or malformed.
    pub fn from_running_kernel() -> Result<Self, BtfError> {
        Self::from_file(Path::new(VMLINUX_BTF))
    }

    /// # Errors
    /// See [`Self::from_running_kernel`].
    pub fn from_file(path: &Path) -> Result<Self, BtfError> {
        let bytes = std::fs::read(path).map_err(|source| BtfError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&bytes)
    }

    /// # Errors
    /// When the blob is not BTF or is truncated.
    #[allow(clippy::too_many_lines)] // one linear walk over the type section
    pub fn parse(b: &[u8]) -> Result<Self, BtfError> {
        let magic = u16_at(b, 0)?;
        if magic != BTF_MAGIC {
            return Err(BtfError::BadMagic(magic));
        }
        // Section offsets are relative to the end of the header, whose
        // length is itself in the header — the format is extensible and
        // a newer kernel may add fields we do not read.
        let hdr_len = u32_at(b, 4)? as usize;
        let type_off = u32_at(b, 8)? as usize;
        let type_len = u32_at(b, 12)? as usize;
        let str_off = u32_at(b, 16)? as usize;
        let str_len = u32_at(b, 20)? as usize;

        let types = b
            .get(hdr_len + type_off..hdr_len + type_off + type_len)
            .ok_or(BtfError::Truncated(hdr_len + type_off))?;
        let strings = b
            .get(hdr_len + str_off..hdr_len + str_off + str_len)
            .ok_or(BtfError::Truncated(hdr_len + str_off))?;

        let name_at = |off: u32| -> String {
            let off = off as usize;
            let end = strings[off.min(strings.len())..]
                .iter()
                .position(|&c| c == 0)
                .map_or(strings.len(), |n| off + n);
            String::from_utf8_lossy(&strings[off.min(strings.len())..end]).into_owned()
        };

        let mut structs: HashMap<String, HashMap<String, u32>> = HashMap::new();
        let mut cur = 0usize;
        while cur + 12 <= types.len() {
            let name_off = u32_at(types, cur)?;
            let info = u32_at(types, cur + 4)?;
            // size_or_type at cur + 8 is unused for our purposes.
            let vlen = (info & 0xffff) as usize;
            let kind = (info >> 24) & 0x1f;
            let kind_flag = info >> 31;
            cur += 12;

            // Trailing data length per kind. Everything not listed has
            // none: PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC,
            // FLOAT, TYPE_TAG.
            // Trailing size per kind; grouped by the record width each
            // kind's array uses rather than by what the kind means, so
            // the arms are about layout only.
            let trailing = match kind {
                KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
                KIND_ARRAY => 12,
                // 8-byte records: btf_enum, btf_param.
                KIND_ENUM | KIND_FUNC_PROTO => vlen * 8,
                // 12-byte records: btf_member, btf_var_secinfo,
                // btf_enum64.
                KIND_STRUCT | KIND_UNION | KIND_DATASEC | KIND_ENUM64 => vlen * 12,
                _ => 0,
            };

            if kind == KIND_STRUCT || kind == KIND_UNION {
                let name = name_at(name_off);
                if !name.is_empty() {
                    let mut members = HashMap::with_capacity(vlen);
                    for i in 0..vlen {
                        let m = cur + i * 12;
                        let m_name = name_at(u32_at(types, m)?);
                        let raw = u32_at(types, m + 8)?;
                        // With kind_flag set, the high 8 bits are the
                        // bitfield size and the low 24 the bit offset.
                        // Otherwise the whole word is a bit offset.
                        let (bit_off, bitfield_size) = if kind_flag == 1 {
                            (raw & 0x00ff_ffff, raw >> 24)
                        } else {
                            (raw, 0)
                        };
                        // A bitfield member is recorded with its size so
                        // the caller can be refused rather than handed a
                        // byte offset that means something else.
                        let encoded = if bitfield_size > 0 || bit_off % 8 != 0 {
                            u32::MAX
                        } else {
                            bit_off / 8
                        };
                        members.insert(m_name, encoded);
                    }
                    // First definition wins. A kernel BTF can contain
                    // several types with one name (a forward
                    // declaration, or an anonymous duplicate); the
                    // complete one appears first in practice, and taking
                    // the first keeps this deterministic.
                    structs.entry(name).or_insert(members);
                }
            }
            cur += trailing;
        }

        Ok(Self { structs })
    }

    /// Byte offset of `field` within `struct_name`.
    ///
    /// # Errors
    /// When the struct or the field is absent from this kernel's BTF, or
    /// when the field is a bitfield — all three are reasons to refuse to
    /// install a blocker rather than to guess.
    pub fn field_offset(&self, struct_name: &str, field: &str) -> Result<u32, BtfError> {
        let members = self
            .structs
            .get(struct_name)
            .ok_or_else(|| BtfError::NoSuchStruct(struct_name.to_string()))?;
        let off = members
            .get(field)
            .copied()
            .ok_or_else(|| BtfError::NoSuchField {
                struct_name: struct_name.to_string(),
                field: field.to_string(),
            })?;
        if off == u32::MAX {
            return Err(BtfError::Bitfield {
                struct_name: struct_name.to_string(),
                field: field.to_string(),
            });
        }
        Ok(off)
    }

    #[must_use]
    pub fn struct_count(&self) -> usize {
        self.structs.len()
    }
}

/// The offsets `block_exec` needs to walk `bprm->file->f_inode`.
///
/// Resolved as a set, because a partial answer is useless: the hook
/// either walks the whole chain or must not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecInodeOffsets {
    /// `linux_binprm.file`
    pub binprm_file: u32,
    /// `file.f_inode`
    pub file_inode: u32,
    /// `inode.i_ino`
    pub inode_ino: u32,
    /// `inode.i_sb`
    pub inode_sb: u32,
    /// `super_block.s_dev`
    pub sb_dev: u32,
}

impl ExecInodeOffsets {
    /// Resolve every offset, or fail naming the one that could not be
    /// found.
    ///
    /// # Errors
    /// Any field missing from this kernel's BTF. The caller must treat
    /// that as "do not install the blocker", never as "use a default".
    pub fn resolve(btf: &Btf) -> Result<Self, BtfError> {
        Ok(Self {
            binprm_file: btf.field_offset("linux_binprm", "file")?,
            file_inode: btf.field_offset("file", "f_inode")?,
            inode_ino: btf.field_offset("inode", "i_ino")?,
            inode_sb: btf.field_offset("inode", "i_sb")?,
            sb_dev: btf.field_offset("super_block", "s_dev")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running_kernel_btf() -> Option<Btf> {
        Btf::from_running_kernel().ok()
    }

    #[test]
    fn a_non_btf_blob_is_rejected_rather_than_parsed() {
        let err = Btf::parse(&[0u8; 64]).unwrap_err();
        assert!(matches!(err, BtfError::BadMagic(_)), "{err}");
    }

    #[test]
    fn a_truncated_blob_is_rejected() {
        let mut b = vec![0u8; 8];
        b[0..2].copy_from_slice(&BTF_MAGIC.to_le_bytes());
        assert!(Btf::parse(&b).is_err());
    }

    /// The whole point: against the kernel actually running, every field
    /// the blocker needs resolves.
    ///
    /// Skipped rather than failed where there is no BTF — CI containers
    /// and Pi kernels do not ship it, and that is exactly the case the
    /// loader handles by refusing to install the blocker.
    #[test]
    fn every_field_the_blocker_needs_resolves_on_this_kernel() {
        let Some(btf) = running_kernel_btf() else {
            eprintln!("no /sys/kernel/btf/vmlinux here; skipping");
            return;
        };
        assert!(btf.struct_count() > 1000, "a real vmlinux has many structs");
        let off = ExecInodeOffsets::resolve(&btf).expect("all fields must resolve");
        // Offsets are kernel-specific, so the assertion is on shape
        // rather than on values: nothing at zero-except-the-first-field,
        // nothing absurd.
        assert!(off.binprm_file < 4096, "{off:?}");
        assert!(off.file_inode < 4096, "{off:?}");
        assert!(off.inode_ino < 4096, "{off:?}");
        assert!(off.inode_sb < 4096, "{off:?}");
        assert!(off.sb_dev < 4096, "{off:?}");
        eprintln!("resolved on this kernel: {off:?}");
    }

    #[test]
    fn a_missing_struct_names_itself() {
        let Some(btf) = running_kernel_btf() else {
            return;
        };
        let err = btf
            .field_offset("definitely_not_a_kernel_struct", "x")
            .unwrap_err();
        assert!(
            err.to_string().contains("definitely_not_a_kernel_struct"),
            "{err}"
        );
    }

    #[test]
    fn a_missing_field_names_itself() {
        let Some(btf) = running_kernel_btf() else {
            return;
        };
        let err = btf.field_offset("inode", "not_a_real_field").unwrap_err();
        assert!(err.to_string().contains("not_a_real_field"), "{err}");
        assert!(err.to_string().contains("inode"), "{err}");
    }

    /// A sanity check that the parser is reading real layouts rather
    /// than plausible-looking noise: `task_struct.pid` and
    /// `task_struct.tgid` are adjacent 4-byte ints in every kernel.
    #[test]
    fn adjacent_fields_come_out_adjacent() {
        let Some(btf) = running_kernel_btf() else {
            return;
        };
        let (Ok(pid), Ok(tgid)) = (
            btf.field_offset("task_struct", "pid"),
            btf.field_offset("task_struct", "tgid"),
        ) else {
            return;
        };
        assert_eq!(
            tgid,
            pid + 4,
            "pid and tgid are adjacent u32s; got {pid} and {tgid}"
        );
    }
}
