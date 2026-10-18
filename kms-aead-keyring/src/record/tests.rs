use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};

use super::*;
use crate::errors::RecordInvalidError;
use crate::test_support::{TestResult, TENANT};

const CREATED: &str = "2026-01-10T09:00:00Z";
const ROTATED: &str = "2026-04-10T09:00:00Z";
const COMPROMISED: &str = "2026-05-01T12:00:00Z";
/// The wrapped bytes of every fixture version: distinctive, so that a test can look for them.
const WRAPPED: [u8; 6] = [0xC0, 0xFF, 0xEE, 0xC0, 0xFF, 0xEE];
/// [`WRAPPED`] in standard base64, as the record stores it.
const WRAPPED_BASE64: &str = "wP/uwP/u";

/// A version as the stored form writes it, with a wrapped key unless it is destroyed.
fn version(key_id: u32, state: &str, compromised: bool) -> KeyringResult<Value> {
    let algorithm = if key_id >> 31 == 1 {
        "aes-256-siv"
    } else {
        "aes-256-gcm"
    };
    let wrapped_dek = match state {
        "destroyed" => Value::Null,
        _ => json!(WRAPPED_BASE64),
    };
    let compromised = match compromised {
        true => json!({ "at": COMPROMISED, "note": "laptop lost" }),
        false => Value::Null,
    };
    Ok(json!({
        "key_id": key_id,
        "algorithm": algorithm,
        "state": state,
        "compromised": compromised,
        "created_at": CREATED,
        "state_changed_at": ROTATED,
        "wrapped_dek": wrapped_dek,
    }))
}

fn document(versions: Vec<Value>) -> Value {
    json!({
        "schema": 1,
        "id": TENANT.as_str(),
        "kek": { "provider": "gcp", "key": "projects/p/locations/europe-west1/keyRings/app/cryptoKeys/keyring-kek" },
        "algorithms": { "randomized": "aes-256-gcm", "deterministic": "aes-256-siv" },
        "versions": versions,
        "created_at": CREATED,
        "updated_at": ROTATED,
    })
}

fn parse(document: &Value) -> KeyringResult<KeyringRecord> {
    KeyringRecord::from_json(&TENANT, document.to_string().as_bytes())
}

/// The reason `document` is refused for, or `None` when it parses.
fn refusal(document: &Value) -> Option<RecordInvalidReason> {
    match parse(document) {
        Err(KeyringError::RecordInvalid(RecordInvalidError { reason, .. })) => Some(reason),
        _ => None,
    }
}

/// A rotated keyring: randomized 1 decrypts only, 2 is active, deterministic 2147483649 is
/// active.
fn rotated() -> KeyringResult<Value> {
    Ok(document(vec![
        version(1, "decrypt_only", false)?,
        version(2, "active", false)?,
        version(0x8000_0001, "active", false)?,
    ]))
}

#[test]
fn a_record_round_trips_through_its_json() -> TestResult {
    let record = parse(&rotated()?)?;
    let reparsed = KeyringRecord::from_json(&TENANT, &record.to_json()?)?;
    assert_eq!(reparsed.to_json()?, record.to_json()?);
    assert_eq!(
        serde_json::from_slice::<Value>(&record.to_json()?)?,
        rotated()?
    );
    assert_eq!(
        reparsed.active(Purpose::Randomized).map(KeyVersion::key_id),
        Some(KeyId::try_from(2)?)
    );
    assert_eq!(
        reparsed.kek(),
        &KekRef::new(
            kms_aead::KekProvider::Gcp,
            "projects/p/locations/europe-west1/keyRings/app/cryptoKeys/keyring-kek"
        )
    );
    Ok(())
}

#[test]
fn two_active_versions_of_one_purpose_are_rejected() -> KeyringResult<()> {
    let document = document(vec![
        version(1, "active", false)?,
        version(2, "active", false)?,
    ]);
    assert_eq!(
        refusal(&document),
        Some(RecordInvalidReason::TwoActiveVersions(Purpose::Randomized))
    );
    Ok(())
}

#[test]
fn an_active_compromised_version_is_rejected() -> KeyringResult<()> {
    let document = document(vec![version(1, "active", true)?]);
    assert_eq!(
        refusal(&document),
        Some(RecordInvalidReason::CompromisedActive(KeyId::try_from(1)?))
    );
    Ok(())
}

#[test]
fn a_destroyed_version_with_material_is_rejected() -> KeyringResult<()> {
    let mut destroyed = version(1, "destroyed", false)?;
    destroyed["wrapped_dek"] = json!(WRAPPED_BASE64);
    assert_eq!(
        refusal(&document(vec![destroyed, version(2, "active", false)?])),
        Some(RecordInvalidReason::DestroyedWithMaterial(KeyId::try_from(
            1
        )?))
    );
    Ok(())
}

#[test]
fn a_version_without_material_is_rejected() -> KeyringResult<()> {
    let mut retired = version(1, "retired", false)?;
    retired["wrapped_dek"] = Value::Null;
    assert_eq!(
        refusal(&document(vec![retired, version(2, "active", false)?])),
        Some(RecordInvalidReason::MissingMaterial(KeyId::try_from(1)?))
    );
    Ok(())
}

#[test]
fn a_key_id_of_the_wrong_purpose_is_rejected() -> KeyringResult<()> {
    let mut deterministic_id = version(1, "active", false)?;
    deterministic_id["key_id"] = json!(0x8000_0001u32);
    assert_eq!(
        refusal(&document(vec![deterministic_id])),
        Some(RecordInvalidReason::PurposeMismatch(KeyId::try_from(
            0x8000_0001
        )?))
    );
    Ok(())
}

#[test]
fn duplicate_key_ids_are_rejected() -> KeyringResult<()> {
    let document = document(vec![
        version(1, "decrypt_only", false)?,
        version(1, "active", false)?,
    ]);
    assert_eq!(
        refusal(&document),
        Some(RecordInvalidReason::DuplicateKeyId(KeyId::try_from(1)?))
    );
    Ok(())
}

#[test]
fn ordinals_out_of_creation_order_are_rejected() -> KeyringResult<()> {
    let document = document(vec![
        version(0x8000_0001, "active", false)?,
        version(2, "decrypt_only", false)?,
        version(1, "active", false)?,
    ]);
    assert_eq!(
        refusal(&document),
        Some(RecordInvalidReason::OrdinalOrder(KeyId::try_from(1)?))
    );
    Ok(())
}

#[test]
fn a_wrapped_dek_that_does_not_parse_is_rejected() -> KeyringResult<()> {
    for wrapped_dek in ["not base64!", ""] {
        let mut active = version(1, "active", false)?;
        active["wrapped_dek"] = json!(wrapped_dek);
        assert_eq!(
            refusal(&document(vec![active])),
            Some(RecordInvalidReason::MalformedWrappedDek(KeyId::try_from(
                1
            )?))
        );
    }
    Ok(())
}

#[test]
fn names_of_other_schemas_algorithms_and_states_are_rejected() -> KeyringResult<()> {
    let mut schema = rotated()?;
    schema["schema"] = json!(2);
    assert_eq!(
        refusal(&schema),
        Some(RecordInvalidReason::UnsupportedSchema(2))
    );

    let mut algorithms = rotated()?;
    algorithms["algorithms"]["randomized"] = json!("aes-512-gcm");
    assert_eq!(
        refusal(&algorithms),
        Some(RecordInvalidReason::UnknownAlgorithm(None))
    );

    let mut algorithm = version(1, "active", false)?;
    algorithm["algorithm"] = json!("aes-256-siv");
    assert_eq!(
        refusal(&document(vec![algorithm])),
        Some(RecordInvalidReason::PurposeMismatch(KeyId::try_from(1)?))
    );

    let mut state = version(1, "active", false)?;
    state["state"] = json!("dormant");
    assert_eq!(
        refusal(&document(vec![state])),
        Some(RecordInvalidReason::UnknownState(KeyId::try_from(1)?))
    );
    Ok(())
}

#[test]
fn a_record_of_another_keyring_is_rejected() -> KeyringResult<()> {
    let mut other = rotated()?;
    other["id"] = json!("tenant-43");
    assert_eq!(refusal(&other), Some(RecordInvalidReason::IdMismatch));
    other["id"] = json!("not a keyring id");
    assert_eq!(refusal(&other), Some(RecordInvalidReason::IdMismatch));
    Ok(())
}

#[test]
fn a_record_over_the_size_cap_is_invalid() -> TestResult {
    let mut document = serde_json::to_vec(&rotated()?)?;
    let padding = (1 << 20) + 1 - document.len();
    document.extend(std::iter::repeat_n(b' ', padding));
    assert!(matches!(
        KeyringRecord::from_json(&TENANT, &document),
        Err(KeyringError::RecordInvalid(RecordInvalidError {
            reason: RecordInvalidReason::TooLarge,
            ..
        }))
    ));
    document.pop();
    KeyringRecord::from_json(&TENANT, &document)?;
    Ok(())
}

#[test]
fn a_malformed_record_error_quotes_no_document_bytes() -> TestResult {
    let mut document = rotated()?;
    document["versions"][0]["key_id"] = json!(WRAPPED_BASE64);
    let error = parse(&document).err();
    assert!(matches!(
        error,
        Some(KeyringError::RecordInvalid(RecordInvalidError {
            reason: RecordInvalidReason::Malformed(_),
            ..
        }))
    ));
    let error = error.ok_or("the document parsed")?;
    for text in [format!("{error}"), format!("{error:?}")] {
        assert!(!text.contains(WRAPPED_BASE64), "{text}");
    }
    Ok(())
}

#[test]
fn record_debug_carries_no_wrapped_dek() -> TestResult {
    let record = parse(&rotated()?)?;
    let debug = format!("{record:?}");
    let byte_list = format!("{:?}", &WRAPPED[..]);
    let lower_hex: String = WRAPPED.iter().map(|byte| format!("{byte:02x}")).collect();
    let upper_hex: String = WRAPPED.iter().map(|byte| format!("{byte:02X}")).collect();
    for marker in [
        WRAPPED_BASE64,
        &lower_hex,
        &upper_hex,
        &byte_list,
        "192, 255, 238",
    ] {
        assert!(!debug.contains(marker), "{marker} in {debug}");
    }
    Ok(())
}

/// The operations a version can be asked for, by the transition each one is.
#[derive(Clone, Copy, Debug)]
enum Operation {
    MarkCompromised,
    Retire,
    Reinstate,
    Destroy,
}

impl Operation {
    const ALL: [Operation; 4] = [
        Operation::MarkCompromised,
        Operation::Retire,
        Operation::Reinstate,
        Operation::Destroy,
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
        }
    }

    fn transition(self) -> Transition {
        match self {
            Operation::MarkCompromised => Transition::MarkCompromised,
            Operation::Retire => Transition::Retire,
            Operation::Reinstate => Transition::Reinstate,
            Operation::Destroy => Transition::Destroy,
        }
    }
}

/// The state and compromised flag each operation of `Operation::ALL` leaves a version in, or
/// `None` where the lifecycle has no such transition.
type Outcomes = [Option<(KeyVersionState, bool)>; 4];

/// Every state a version can be in, compromised or not, with its outcomes.
fn lifecycle() -> [(&'static str, bool, Outcomes); 7] {
    use KeyVersionState::*;
    [
        (
            "active",
            false,
            [Some((DecryptOnly, true)), None, None, None],
        ),
        (
            "decrypt_only",
            false,
            [
                Some((DecryptOnly, true)),
                Some((Retired, false)),
                None,
                None,
            ],
        ),
        (
            "decrypt_only",
            true,
            [None, Some((Retired, true)), None, None],
        ),
        (
            "retired",
            false,
            [
                Some((Retired, true)),
                None,
                Some((DecryptOnly, false)),
                Some((Destroyed, false)),
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
            ],
        ),
        ("destroyed", false, [None, None, None, None]),
        ("destroyed", true, [None, None, None, None]),
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
            operation.apply(&mut edit, KeyId::try_from(1)?)?;
            let version = edit
                .record()
                .version(KeyId::try_from(1)?)
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
                version.wrapped_dek().is_some(),
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
                    operation.apply(&mut edit, KeyId::try_from(1)?),
                    Err(KeyringError::InvalidTransition(error))
                        if error.transition == operation.transition() && error.key_id == KeyId::try_from(1)?
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
        edit.retire(KeyId::try_from(9)?, Timestamp::now()),
        Err(KeyringError::KeyVersionUnknown(error)) if error.key_id == KeyId::try_from(9)?
    ));
    Ok(())
}

/// The next version of `algorithm`'s purpose in `record`.
fn new_version(record: &KeyringRecord, algorithm: KeyAlgorithm) -> KeyringResult<NewVersion> {
    Ok(NewVersion {
        key_id: record.next_key_id(algorithm.purpose())?,
        algorithm,
        dek: EncryptedDataEncryptionKey::new(WRAPPED.to_vec()),
    })
}

#[test]
fn rotation_takes_the_next_key_id_of_its_purpose() -> KeyringResult<()> {
    let mut edit = RecordEdit::from(parse(&rotated()?)?);
    let now = Timestamp::now();
    let rotation = edit.rotate(
        new_version(
            edit.record(),
            KeyAlgorithm::Randomized(AeadAlgorithm::Aes256Gcm),
        )?,
        now,
    )?;
    assert_eq!(
        rotation,
        Rotation {
            purpose: Purpose::Randomized,
            previous: Some(KeyId::try_from(2)?),
            current: KeyId::try_from(3)?,
        }
    );
    let rotation = edit.rotate(
        new_version(
            edit.record(),
            KeyAlgorithm::Deterministic(DeterministicAlgorithm::Aes256Siv),
        )?,
        now,
    )?;
    assert_eq!(rotation.current, KeyId::try_from(0x8000_0002)?);
    let record = edit.finish()?;
    assert_eq!(
        record.version(KeyId::try_from(2)?).map(KeyVersion::state),
        Some(KeyVersionState::DecryptOnly)
    );
    assert_eq!(record.updated_at(), now);
    Ok(())
}

#[test]
fn rotation_without_an_active_version_creates_one() -> KeyringResult<()> {
    let mut edit = RecordEdit::from(parse(&document(vec![version(1, "decrypt_only", true)?]))?);
    let rotation = edit.rotate(
        new_version(
            edit.record(),
            KeyAlgorithm::Randomized(AeadAlgorithm::Aes256Gcm),
        )?,
        Timestamp::now(),
    )?;
    assert_eq!(
        (rotation.previous, rotation.current),
        (None, KeyId::try_from(2)?)
    );
    Ok(())
}

#[test]
fn compromising_the_active_version_rotates_in_the_same_change() -> KeyringResult<()> {
    let now = Timestamp::now();
    let mut edit = RecordEdit::from(parse(&rotated()?)?);
    let replacement = new_version(
        edit.record(),
        KeyAlgorithm::Randomized(AeadAlgorithm::Aes256Gcm),
    )?;
    let rotation = edit.mark_compromised(
        KeyId::try_from(2)?,
        Compromise::new(now, Some("leaked".to_string())),
        Some(replacement),
        now,
    )?;
    assert_eq!(
        rotation.map(|rotation| (rotation.previous, rotation.current)),
        Some((Some(KeyId::try_from(2)?), KeyId::try_from(3)?))
    );
    assert_eq!(
        edit.record()
            .active(Purpose::Randomized)
            .map(KeyVersion::key_id),
        Some(KeyId::try_from(3)?)
    );

    let mut flag_alone = RecordEdit::from(parse(&rotated()?)?);
    let rotation =
        flag_alone.mark_compromised(KeyId::try_from(2)?, Compromise::new(now, None), None, now)?;
    assert_eq!(rotation, None);
    assert!(flag_alone.finish()?.active(Purpose::Randomized).is_none());
    Ok(())
}

/// The held record of the regression cases: randomized 1 compromised and decrypt-only, 2
/// active, 3 retired, 4 destroyed.
fn held() -> KeyringResult<Value> {
    Ok(document(vec![
        version(1, "decrypt_only", true)?,
        version(2, "active", false)?,
        version(3, "retired", false)?,
        version(4, "destroyed", false)?,
    ]))
}

#[test]
fn a_regressed_record_is_refused() -> TestResult {
    type Change = fn(&mut Value);
    let cases: [(Change, RegressionRule); 6] = [
        (
            |next| {
                if let Some(versions) = next["versions"].as_array_mut() {
                    versions.remove(0);
                }
            },
            RegressionRule::VersionMissing(KeyId::try_from(1)?),
        ),
        (
            |next| next["versions"][1]["created_at"] = json!(ROTATED),
            RegressionRule::VersionAltered(KeyId::try_from(2)?),
        ),
        (
            |next| next["versions"][0]["compromised"] = Value::Null,
            RegressionRule::CompromiseCleared(KeyId::try_from(1)?),
        ),
        (
            |next| next["versions"][0]["compromised"]["at"] = json!(ROTATED),
            RegressionRule::CompromiseAltered(KeyId::try_from(1)?),
        ),
        (
            |next| {
                next["versions"][1]["state"] = json!("decrypt_only");
                next["versions"][2]["state"] = json!("active");
            },
            RegressionRule::StateReverted(KeyId::try_from(3)?),
        ),
        (
            |next| {
                next["versions"][3]["state"] = json!("retired");
                next["versions"][3]["wrapped_dek"] =
                    json!(STANDARD.encode([0xFF, 0x01, 0x00, 0x2A]));
            },
            RegressionRule::StateReverted(KeyId::try_from(4)?),
        ),
    ];
    let held_record = parse(&held()?)?;
    for (change, rule) in cases {
        let mut next = held()?;
        change(&mut next);
        let next = parse(&next)?;
        assert_eq!(check_successor(&held_record, &next), Err(rule));
    }
    Ok(())
}

#[test]
fn forward_moves_are_accepted_however_many_steps_they_skip() -> TestResult {
    let held_record = parse(&held()?)?;
    let mut next = held()?;
    next["versions"][0]["state"] = json!("destroyed");
    next["versions"][0]["wrapped_dek"] = Value::Null;
    next["versions"][1]["state"] = json!("retired");
    next["versions"][2]["state"] = json!("decrypt_only");
    next["versions"][2]["compromised"] = json!({ "at": COMPROMISED, "note": null });
    if let Some(versions) = next["versions"].as_array_mut() {
        versions.push(version(5, "active", false)?);
    }
    assert_eq!(check_successor(&held_record, &parse(&next)?), Ok(()));
    assert_eq!(check_successor(&held_record, &held_record), Ok(()));
    Ok(())
}

#[test]
fn versions_taken_out_of_use_are_withdrawn() -> TestResult {
    let mut held_document = held()?;
    held_document["versions"][2]["state"] = json!("decrypt_only");
    let held_record = parse(&held_document)?;

    let mut next = held_document.clone();
    next["versions"][1]["state"] = json!("decrypt_only");
    next["versions"][1]["compromised"] = json!({ "at": COMPROMISED, "note": null });
    next["versions"][2]["state"] = json!("retired");
    if let Some(versions) = next["versions"].as_array_mut() {
        versions.push(version(5, "active", false)?);
    }
    let next = parse(&next)?;
    assert_eq!(withdrawn_deks(&held_record, &next).count(), 2);
    assert_eq!(withdrawn_deks(&held_record, &held_record).count(), 0);
    Ok(())
}

#[test]
fn a_rewrapped_key_withdraws_the_bytes_it_replaces() -> TestResult {
    let held_record = parse(&held()?)?;
    let mut next = held()?;
    next["versions"][1]["wrapped_dek"] = json!(STANDARD.encode([0x0B, 0xAD]));
    let next = parse(&next)?;
    let withdrawn: Vec<_> = withdrawn_deks(&held_record, &next).collect();
    assert_eq!(
        withdrawn,
        [(
            KeyId::try_from(2)?,
            &EncryptedDataEncryptionKey::new(WRAPPED.to_vec())
        )]
    );
    Ok(())
}

#[test]
fn dot_and_dotdot_keyring_ids_are_rejected() -> KeyringResult<()> {
    for id in [".", "..", "__x__", "____"] {
        assert!(matches!(
            KeyringId::try_from(id),
            Err(KeyringError::InvalidIdentifier(error))
                if error.identifier == Identifier::KeyringId && error.rule == IdentifierRule::Reserved
        ));
    }
    for id in ["...", "__x", "x__", "__", "a.b", "tenant_42-eu"] {
        KeyringId::try_from(id)?;
    }
    Ok(())
}

#[test]
#[should_panic]
fn a_static_keyring_id_is_checked_like_any_other() {
    KeyringId::from_static("..");
}

#[test]
fn keyring_ids_are_ascii_and_at_most_128_bytes() -> KeyringResult<()> {
    KeyringId::try_from("k".repeat(128))?;
    for (id, rule) in [
        (String::new(), IdentifierRule::Length),
        ("k".repeat(129), IdentifierRule::Length),
        ("tenant/42".to_string(), IdentifierRule::Character),
        ("tenänt".to_string(), IdentifierRule::Character),
    ] {
        assert!(matches!(
            KeyringId::try_from(id),
            Err(KeyringError::InvalidIdentifier(error)) if error.rule == rule
        ));
    }
    Ok(())
}

#[test]
fn state_and_algorithm_names_parse_back() -> TestResult {
    for state in [
        KeyVersionState::Active,
        KeyVersionState::DecryptOnly,
        KeyVersionState::Retired,
        KeyVersionState::Destroyed,
    ] {
        assert_eq!(state.to_string().parse::<KeyVersionState>()?, state);
    }
    for algorithm in [
        KeyAlgorithm::Randomized(AeadAlgorithm::Aes256Gcm),
        KeyAlgorithm::Deterministic(DeterministicAlgorithm::Aes256Siv),
    ] {
        assert_eq!(algorithm.to_string().parse::<KeyAlgorithm>()?, algorithm);
    }
    assert!(matches!(
        "compromised".parse::<KeyVersionState>(),
        Err(KeyringError::UnknownKeyVersionState)
    ));
    assert!(matches!(
        "aes-128-siv".parse::<KeyAlgorithm>(),
        Err(error) if error.code() == "UNKNOWN_ALGORITHM"
    ));
    Ok(())
}
