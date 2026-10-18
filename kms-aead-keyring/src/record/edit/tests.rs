use kms_aead::{AeadAlgorithm, DeterministicAlgorithm};
use serde_json::json;

use super::*;
use crate::errors::RecordInvalidError;
use crate::record::tests::{document, parse, rotated, version, COMPROMISED, ENCRYPTED_DEK};
use crate::test_support::TestResult;

/// The operations a version can be asked for, by the transition each one is.
#[derive(Clone, Copy, Debug)]
enum Operation {
    MarkCompromised,
    Retire,
    Reinstate,
    Destroy,
    Promote,
}

impl Operation {
    const ALL: [Operation; 5] = [
        Operation::MarkCompromised,
        Operation::Retire,
        Operation::Reinstate,
        Operation::Destroy,
        Operation::Promote,
    ];

    fn apply(self, edit: &mut RecordEdit, key_id: KeyId) -> KeyringResult<()> {
        let now = Timestamp::now();
        match self {
            Operation::MarkCompromised => edit
                .mark_compromised(key_id, Compromise::new(now, None), None, now)
                .map(|_| ()),
            Operation::Retire => edit.retire(key_id, now),
            Operation::Reinstate => edit.reinstate(key_id, now),
            Operation::Destroy => edit.destroy(key_id, now),
            Operation::Promote => edit.promote(key_id, now).map(|_| ()),
        }
    }

    fn transition(self) -> Transition {
        match self {
            Operation::MarkCompromised => Transition::MarkCompromised,
            Operation::Retire => Transition::Retire,
            Operation::Reinstate => Transition::Reinstate,
            Operation::Destroy => Transition::Destroy,
            Operation::Promote => Transition::Promote,
        }
    }
}

/// The state and compromised flag each operation of `Operation::ALL` leaves a version in, or
/// `None` where the lifecycle has no such transition.
type Outcomes = [Option<(KeyVersionState, bool)>; 5];

/// Every state a version can be in, compromised or not, with its outcomes.
fn lifecycle() -> [(&'static str, bool, Outcomes); 8] {
    use KeyVersionState::*;
    [
        (
            "pending",
            false,
            [
                None,
                None,
                None,
                Some((Destroyed, false)),
                Some((Active, false)),
            ],
        ),
        (
            "active",
            false,
            [Some((DecryptOnly, true)), None, None, None, None],
        ),
        (
            "decrypt_only",
            false,
            [
                Some((DecryptOnly, true)),
                Some((Retired, false)),
                None,
                None,
                None,
            ],
        ),
        (
            "decrypt_only",
            true,
            [None, Some((Retired, true)), None, None, None],
        ),
        (
            "retired",
            false,
            [
                Some((Retired, true)),
                None,
                Some((DecryptOnly, false)),
                Some((Destroyed, false)),
                None,
            ],
        ),
        (
            "retired",
            true,
            [
                None,
                None,
                Some((DecryptOnly, true)),
                Some((Destroyed, true)),
                None,
            ],
        ),
        ("destroyed", false, [None, None, None, None, None]),
        ("destroyed", true, [None, None, None, None, None]),
    ]
}

#[test]
fn every_transition_of_the_lifecycle_is_accepted() -> TestResult {
    for (state, compromised, outcomes) in lifecycle() {
        for (operation, outcome) in Operation::ALL.into_iter().zip(outcomes) {
            let Some((expected_state, expected_compromised)) = outcome else {
                continue;
            };
            let mut edit =
                RecordEdit::from(parse(&document(vec![version(1, state, compromised)?]))?);
            operation.apply(&mut edit, KeyId::new(1))?;
            let version = edit
                .record()
                .version(KeyId::new(1))
                .ok_or("version 1 is gone")?;
            assert_eq!(
                (version.state(), version.compromised().is_some()),
                (expected_state, expected_compromised),
                "{operation:?} on {state}, compromised {compromised}"
            );
            if compromised {
                assert_eq!(
                    version.compromised().map(Compromise::at),
                    Some(COMPROMISED.parse::<Timestamp>()?),
                    "the flag keeps its time"
                );
            }
            assert_eq!(
                version.encrypted_dek().is_some(),
                expected_state != KeyVersionState::Destroyed
            );
            edit.finish()?;
        }
    }
    Ok(())
}

#[test]
fn every_other_transition_is_refused() -> KeyringResult<()> {
    for (state, compromised, outcomes) in lifecycle() {
        for (operation, outcome) in Operation::ALL.into_iter().zip(outcomes) {
            if outcome.is_some() {
                continue;
            }
            let mut edit =
                RecordEdit::from(parse(&document(vec![version(1, state, compromised)?]))?);
            let before = edit.record().to_json()?;
            assert!(
                matches!(
                    operation.apply(&mut edit, KeyId::new(1)),
                    Err(KeyringError::InvalidTransition(error))
                        if error.transition == operation.transition() && error.key_id == KeyId::new(1)
                ),
                "{operation:?} on {state}, compromised {compromised}"
            );
            assert_eq!(
                edit.record().to_json()?,
                before,
                "a refused transition changes nothing"
            );
        }
    }
    Ok(())
}

#[test]
fn an_unknown_key_id_is_no_transition() -> KeyringResult<()> {
    let mut edit = RecordEdit::from(parse(&rotated()?)?);
    assert!(matches!(
        edit.retire(KeyId::new(9), Timestamp::now()),
        Err(KeyringError::KeyVersionUnknown(error)) if error.key_id == KeyId::new(9)
    ));
    Ok(())
}

/// A new version of `algorithm`.
fn new_version(algorithm: KeyAlgorithm) -> NewVersion {
    NewVersion {
        algorithm,
        encrypted_dek: EncryptedDataEncryptionKey::new(ENCRYPTED_DEK.to_vec()),
    }
}

#[test]
fn a_rotation_stages_the_next_key_id_of_its_purpose() -> TestResult {
    let mut edit = RecordEdit::from(parse(&rotated()?)?);
    let now = Timestamp::now();
    let randomized = KeyAlgorithm::Randomized(AeadAlgorithm::Aes256Gcm);
    let staged = edit.stage(new_version(randomized), now)?;
    let deterministic = KeyAlgorithm::Deterministic(DeterministicAlgorithm::Aes256Siv);
    let staged_deterministic = edit.stage(new_version(deterministic), now)?;

    assert_eq!(
        (staged, staged_deterministic),
        (KeyId::new(3), KeyId::new(0x8000_0002))
    );
    assert!(matches!(
        edit.stage(new_version(randomized), now),
        Err(KeyringError::InvalidTransition(error))
            if error.key_id == staged
                && error.from == KeyVersionState::Pending
                && error.transition == Transition::Rotate
    ));
    let record = edit.finish()?;
    let version = record.version(staged).ok_or("the staged version is gone")?;
    assert_eq!(version.state(), KeyVersionState::Pending);
    assert_eq!(version.staged_at(), Some(now));
    assert_eq!(
        record.active(Purpose::Randomized).map(KeyVersion::id),
        Some(KeyId::new(2))
    );
    assert_eq!(record.updated_at(), now);
    Ok(())
}

#[test]
fn a_promotion_moves_the_active_version_to_decrypt_only() -> TestResult {
    let now = Timestamp::now();
    let mut edit = RecordEdit::from(parse(&document(vec![
        version(1, "decrypt_only", false)?,
        version(2, "active", false)?,
        version(3, "pending", false)?,
    ]))?);
    let rotation = edit.promote(KeyId::new(3), now)?;
    assert_eq!(
        rotation,
        Rotation {
            purpose: Purpose::Randomized,
            previous: Some(KeyId::new(2)),
            current: KeyId::new(3),
        }
    );
    let record = edit.finish()?;
    assert_eq!(
        record.version(KeyId::new(2)).map(KeyVersion::state),
        Some(KeyVersionState::DecryptOnly)
    );
    assert_eq!(
        record.version(KeyId::new(3)).map(KeyVersion::staged_at),
        Some(None)
    );

    let mut without_active = RecordEdit::from(parse(&document(vec![
        version(1, "decrypt_only", true)?,
        version(2, "pending", false)?,
    ]))?);
    let rotation = without_active.promote(KeyId::new(2), now)?;
    assert_eq!((rotation.previous, rotation.current), (None, KeyId::new(2)));
    Ok(())
}

#[test]
fn an_activation_past_the_last_seal_epoch_is_refused() -> TestResult {
    let mut last_epoch = document(vec![
        version(1, "active", false)?,
        version(2, "pending", false)?,
    ]);
    last_epoch["seal_epoch"] = json!(u32::MAX);
    let mut edit = RecordEdit::from(parse(&last_epoch)?);

    edit.promote(KeyId::new(2), Timestamp::now())?;

    assert!(matches!(
        edit.finish(),
        Err(KeyringError::RecordInvalid(RecordInvalidError {
            reason: RecordInvalidReason::SealEpochOutOfRange,
            ..
        }))
    ));
    Ok(())
}

#[test]
fn compromising_the_active_version_rotates_in_the_same_change() -> KeyringResult<()> {
    let now = Timestamp::now();
    let mut edit = RecordEdit::from(parse(&rotated()?)?);
    let replacement = new_version(KeyAlgorithm::Randomized(AeadAlgorithm::Aes256Gcm));
    let rotation = edit.mark_compromised(
        KeyId::new(2),
        Compromise::new(now, Some("leaked".to_string())),
        Some(replacement),
        now,
    )?;
    assert_eq!(
        rotation.map(|rotation| (rotation.previous, rotation.current)),
        Some((Some(KeyId::new(2)), KeyId::new(3)))
    );
    assert_eq!(
        edit.record()
            .active(Purpose::Randomized)
            .map(KeyVersion::id),
        Some(KeyId::new(3))
    );

    let mut flag_alone = RecordEdit::from(parse(&rotated()?)?);
    let rotation =
        flag_alone.mark_compromised(KeyId::new(2), Compromise::new(now, None), None, now)?;
    assert_eq!(rotation, None);
    assert!(flag_alone.finish()?.active(Purpose::Randomized).is_none());
    Ok(())
}

#[test]
fn a_compromise_replacement_is_active_beside_a_pending_version() -> KeyringResult<()> {
    let now = Timestamp::now();
    let mut edit = RecordEdit::from(parse(&document(vec![
        version(1, "active", false)?,
        version(2, "pending", false)?,
    ]))?);
    let replacement = new_version(KeyAlgorithm::Randomized(AeadAlgorithm::Aes256Gcm));
    let rotation = edit.mark_compromised(
        KeyId::new(1),
        Compromise::new(now, None),
        Some(replacement),
        now,
    )?;
    assert_eq!(
        rotation.map(|rotation| rotation.current),
        Some(KeyId::new(3))
    );
    let record = edit.finish()?;
    assert_eq!(
        record.active(Purpose::Randomized).map(KeyVersion::id),
        Some(KeyId::new(3))
    );
    assert_eq!(
        record.version(KeyId::new(2)).map(KeyVersion::state),
        Some(KeyVersionState::Pending)
    );
    Ok(())
}
