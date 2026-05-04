//! Phase-8 slice 4: tamper coverage for [`AuditEnvelope`].
//!
//! Existing unit tests cover specific tamper modes (changing
//! `episode_id`, swapping verifying keys). These proptests beat
//! every record field with random mutations and verify the
//! envelope rejects.
//!
//! Properties checked:
//!
//! 1. **Field mutation invalidates verify** — for any record
//!    field we substitute a different value, `verify` fails.
//! 2. **Foreign signature fails** — replacing the signature with a
//!    valid signature produced by a different key fails verify.
//! 3. **Sig-byte flip fails** — flipping any single byte of the
//!    decoded signature fails verify.
//! 4. **Host-fp mismatch caught early** — an envelope whose
//!    `host_fp_hex` doesn't match the supplied verifying key fails
//!    with `FingerprintMismatch` (without ever reaching the sig
//!    check).

use bowery_crypto::Identity;
use bowery_response::{Action, ActionOutcome, AuditEnvelope, AuditError, AuditRecord};
use proptest::prelude::*;

fn arb_action() -> impl Strategy<Value = Action> {
    prop_oneof![
        (any::<u32>(), "[a-z0-9-]{1,32}").prop_map(|(pid, ep)| Action::KillProcess {
            pid,
            episode_id: ep,
        }),
        ("[a-z0-9_-]{1,15}", "[a-z0-9-]{1,32}").prop_map(|(comm, ep)| Action::BlockExec {
            comm,
            episode_id: ep,
        }),
    ]
}

fn arb_outcome() -> impl Strategy<Value = ActionOutcome> {
    prop_oneof![
        any::<u64>().prop_map(|t| ActionOutcome::Executed { at_unix_ms: t }),
        Just(ActionOutcome::AlreadyGone),
        "[a-z0-9 _-]{1,40}".prop_map(ActionOutcome::suppressed),
    ]
}

fn arb_record(host_fp_hex: String) -> impl Strategy<Value = AuditRecord> {
    (
        "[a-z0-9-]{4,32}", // engine
        arb_action(),
        arb_outcome(),
        any::<u64>(), // recorded_at_unix_ms
    )
        .prop_map(move |(engine, action, outcome, ts)| {
            // The record's episode_id mirrors the action's so the
            // shape matches what the agent actually emits.
            let record_episode = match &action {
                Action::KillProcess { episode_id, .. } | Action::BlockExec { episode_id, .. } => {
                    episode_id.clone()
                }
            };
            AuditRecord {
                version: AuditRecord::VERSION,
                host_fp_hex: host_fp_hex.clone(),
                engine,
                episode_id: record_episode,
                action_id: action.id().to_string(),
                action,
                outcome,
                recorded_at_unix_ms: ts,
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        ..ProptestConfig::default()
    })]

    /// Mutating the engine field must invalidate the signature.
    #[test]
    fn engine_mutation_fails_verify(
        new_engine in "[a-z0-9-]{4,32}",
    ) {
        let id = Identity::generate();
        let host_fp = id.fingerprint();
        let mut record = AuditRecord::new(
            &host_fp,
            "process-kill",
            "ep-x",
            Action::KillProcess { pid: 42, episode_id: "ep-x".into() },
            ActionOutcome::executed_now(),
        );
        let mut env = AuditEnvelope::sign(record.clone(), &id).unwrap();
        prop_assume!(env.record.engine != new_engine);
        record.engine = new_engine;
        env.record = record;
        let err = env.verify(&id.verifying_key()).expect_err("tampered engine must reject");
        prop_assert!(matches!(err, AuditError::BadSignature));
    }

    /// Mutating the recorded_at_unix_ms must invalidate the signature.
    #[test]
    fn timestamp_mutation_fails_verify(
        delta in 1u64..1_000_000,
    ) {
        let id = Identity::generate();
        let host_fp = id.fingerprint();
        let record = AuditRecord::new(
            &host_fp,
            "noop",
            "ep-y",
            Action::BlockExec { comm: "nc".into(), episode_id: "ep-y".into() },
            ActionOutcome::AlreadyGone,
        );
        let mut env = AuditEnvelope::sign(record, &id).unwrap();
        env.record.recorded_at_unix_ms = env.record.recorded_at_unix_ms.wrapping_add(delta);
        let err = env.verify(&id.verifying_key()).expect_err("tampered timestamp must reject");
        prop_assert!(matches!(err, AuditError::BadSignature));
    }

    /// Mutating the embedded action's nested fields must invalidate
    /// the signature even though `action_id` stays the same.
    #[test]
    fn nested_action_mutation_fails_verify(
        new_pid in any::<u32>(),
    ) {
        let id = Identity::generate();
        let host_fp = id.fingerprint();
        let record = AuditRecord::new(
            &host_fp,
            "process-kill",
            "ep-z",
            Action::KillProcess { pid: 7, episode_id: "ep-z".into() },
            ActionOutcome::executed_now(),
        );
        prop_assume!(new_pid != 7);
        let mut env = AuditEnvelope::sign(record, &id).unwrap();
        if let Action::KillProcess { ref mut pid, .. } = env.record.action {
            *pid = new_pid;
        }
        let err = env.verify(&id.verifying_key()).expect_err("tampered pid must reject");
        prop_assert!(matches!(err, AuditError::BadSignature));
    }

    /// Replacing the signature with one produced by a foreign key
    /// over the same record bytes must fail under the original key.
    /// (The record's `host_fp_hex` is left as the owner's so the
    /// fingerprint check passes and we exercise the sig path
    /// specifically.)
    #[test]
    fn foreign_signature_fails_verify(
        rec_template in arb_record(String::new()),
    ) {
        let owner = Identity::generate();
        let foreign = Identity::generate();
        let mut record = rec_template;
        record.host_fp_hex = owner.fingerprint().to_hex();

        let mut env = AuditEnvelope::sign(record.clone(), &owner).unwrap();
        let foreign_env = AuditEnvelope::sign(record, &foreign).unwrap();
        env.sig_hex = foreign_env.sig_hex;

        let err = env.verify(&owner.verifying_key()).expect_err("foreign sig must reject");
        prop_assert!(matches!(err, AuditError::BadSignature));
    }

    /// Flipping any single byte of the decoded signature must fail.
    #[test]
    fn sig_byte_flip_fails_verify(
        byte_idx in 0usize..64,
        flip_mask in 1u8..=255,
    ) {
        let id = Identity::generate();
        let record = AuditRecord::new(
            &id.fingerprint(),
            "process-kill",
            "ep-flip",
            Action::KillProcess { pid: 1, episode_id: "ep-flip".into() },
            ActionOutcome::executed_now(),
        );
        let mut env = AuditEnvelope::sign(record, &id).unwrap();
        let mut sig_bytes = hex::decode(&env.sig_hex).unwrap();
        sig_bytes[byte_idx] ^= flip_mask;
        env.sig_hex = hex::encode(sig_bytes);
        let result = env.verify(&id.verifying_key());
        prop_assert!(
            result.is_err(),
            "flipped sig byte {} mask {:#x} unexpectedly verified",
            byte_idx, flip_mask
        );
    }

    /// host_fp_hex inconsistency with the verifying key must surface
    /// as FingerprintMismatch, not BadSignature.
    #[test]
    fn host_fp_mismatch_caught_early(
        delta in 1u8..=255,
    ) {
        let id = Identity::generate();
        let record = AuditRecord::new(
            &id.fingerprint(),
            "noop",
            "ep-fp",
            Action::KillProcess { pid: 1, episode_id: "ep-fp".into() },
            ActionOutcome::suppressed("test"),
        );
        let mut env = AuditEnvelope::sign(record, &id).unwrap();
        // Tweak one byte of the host_fp_hex (decode → flip → re-encode
        // so the result is still valid hex and parses as a Fingerprint).
        let mut fp_bytes = hex::decode(&env.record.host_fp_hex).unwrap();
        fp_bytes[0] ^= delta;
        env.record.host_fp_hex = hex::encode(fp_bytes);
        let err = env.verify(&id.verifying_key()).expect_err("fp mismatch must reject");
        prop_assert!(
            matches!(err, AuditError::FingerprintMismatch),
            "expected FingerprintMismatch, got {:?}", err
        );
    }
}
