use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};

use super::stored::StoredRecord;
use super::*;
use crate::errors::RecordInvalidError;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const KEYRING: &str = "tenant-42";
const CREATED: &str = "2026-01-10T09:00:00Z";
const ROTATED: &str = "2026-04-10T09:00:00Z";
const COMPROMISED: &str = "2026-05-01T12:00:00Z";
/// The wrapped bytes of every fixture version: distinctive, so that a test can look for them.
const WRAPPED: [u8; 6] = [0xC0, 0xFF, 0xEE, 0xC0, 0xFF, 0xEE];

fn keyring_id() -> KeyringResult<KeyringId> {
    KeyringId::try_from(KEYRING)
}

fn wrapped_dek() -> KeyringResult<EncryptedDataEncryptionKey> {
    Ok(EncryptedDataEncryptionKey::new(WRAPPED.to_vec(), None))
}

fn wrapped_dek_base64() -> KeyringResult<String> {
    Ok(STANDARD.encode(wrapped_dek()?.to_bytes()?))
}

/// A version as the stored form writes it, with a wrapped key unless it is destroyed.
fn version(key_id: u32, state: &str, compromised: bool) -> KeyringResult<Value> {
    let algorithm = if key_id >> 31 == 1 {
        "aes-256-siv"
    } else {
        "aes-256-gcm"
    };
    let wrapped_dek = match state {
        "destroyed" => Value::Null,
        _ => Value::String(wrapped_dek_base64()?),
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
        "id": KEYRING,
        "kek": { "provider": "gcp", "key": "projects/p/locations/europe-west1/keyRings/app/cryptoKeys/keyring-kek" },
        "algorithms": { "randomized": "aes-256-gcm", "deterministic": "aes-256-siv" },
        "versions": versions,
        "created_at": CREATED,
        "updated_at": ROTATED,
    })
}

fn parse(document: &Value) -> KeyringResult<KeyringRecord> {
    KeyringRecord::from_json(&keyring_id()?, document.to_string().as_bytes())
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

fn key_id(id: u32) -> KeyringResult<KeyId> {
    KeyId::try_from(id)
}

fn timestamp(text: &str) -> Result<Timestamp, jiff::Error> {
    text.parse()
}

#[test]
fn a_record_round_trips_through_its_json() -> TestResult {
    let record = parse(&rotated()?)?;
    let reparsed = KeyringRecord::from_json(&keyring_id()?, &record.to_json()?)?;
    assert_eq!(reparsed.to_json()?, record.to_json()?);
    assert_eq!(
        serde_json::from_slice::<Value>(&record.to_json()?)?,
        rotated()?
    );
    assert_eq!(
        reparsed.active(Purpose::Randomized).map(KeyVersion::key_id),
        Some(key_id(2)?)
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
        Some(RecordInvalidReason::CompromisedActive(key_id(1)?))
    );
    Ok(())
}

#[test]
fn a_destroyed_version_with_material_is_rejected() -> KeyringResult<()> {
    let mut destroyed = version(1, "destroyed", false)?;
    destroyed["wrapped_dek"] = Value::String(wrapped_dek_base64()?);
    assert_eq!(
        refusal(&document(vec![destroyed, version(2, "active", false)?])),
        Some(RecordInvalidReason::DestroyedWithMaterial(key_id(1)?))
    );
    Ok(())
}

#[test]
fn a_version_without_material_is_rejected() -> KeyringResult<()> {
    let mut retired = version(1, "retired", false)?;
    retired["wrapped_dek"] = Value::Null;
    assert_eq!(
        refusal(&document(vec![retired, version(2, "active", false)?])),
        Some(RecordInvalidReason::MissingMaterial(key_id(1)?))
    );
    Ok(())
}

#[test]
fn a_key_id_of_the_wrong_purpose_is_rejected() -> KeyringResult<()> {
    let mut deterministic_id = version(1, "active", false)?;
    deterministic_id["key_id"] = json!(0x8000_0001u32);
    assert_eq!(
        refusal(&document(vec![deterministic_id])),
        Some(RecordInvalidReason::PurposeMismatch(key_id(0x8000_0001)?))
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
        Some(RecordInvalidReason::DuplicateKeyId(key_id(1)?))
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
        Some(RecordInvalidReason::OrdinalOrder(key_id(1)?))
    );
    Ok(())
}

#[test]
fn a_wrapped_dek_that_does_not_parse_is_rejected() -> KeyringResult<()> {
    for wrapped_dek in ["not base64!", "AAAA"] {
        let mut active = version(1, "active", false)?;
        active["wrapped_dek"] = json!(wrapped_dek);
        assert_eq!(
            refusal(&document(vec![active])),
            Some(RecordInvalidReason::WrappedDek(key_id(1)?))
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
        Some(RecordInvalidReason::PurposeMismatch(key_id(1)?))
    );

    let mut state = version(1, "active", false)?;
    state["state"] = json!("dormant");
    assert_eq!(
        refusal(&document(vec![state])),
        Some(RecordInvalidReason::UnknownState(key_id(1)?))
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
        KeyringRecord::from_json(&keyring_id()?, &document),
        Err(KeyringError::RecordInvalid(RecordInvalidError {
            reason: RecordInvalidReason::TooLarge,
            ..
        }))
    ));
    document.pop();
    KeyringRecord::from_json(&keyring_id()?, &document)?;
    Ok(())
}

#[test]
fn a_record_over_the_version_cap_is_invalid() -> TestResult {
    let destroyed = version(1, "destroyed", false)?;
    let versions = (1..=10_001)
        .map(|id| {
            let mut version = destroyed.clone();
            version["key_id"] = json!(id);
            version
        })
        .collect();
    let stored: StoredRecord = serde_json::from_value(document(versions))?;
    assert!(matches!(
        KeyringRecord::from_stored(&keyring_id()?, stored),
        Err(KeyringError::RecordInvalid(RecordInvalidError {
            reason: RecordInvalidReason::TooManyVersions,
            ..
        }))
    ));
    Ok(())
}

#[test]
fn a_malformed_record_error_quotes_no_document_bytes() -> TestResult {
    let marker = wrapped_dek_base64()?;
    let mut document = rotated()?;
    document["versions"][0]["key_id"] = json!(marker);
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
        assert!(!text.contains(&marker), "{text}");
    }
    Ok(())
}

#[test]
fn record_debug_carries_no_wrapped_dek() -> TestResult {
    let record = parse(&rotated()?)?;
    let debug = format!("{record:?}");
    let base64 = wrapped_dek_base64()?;
    let bytes = wrapped_dek()?.to_bytes()?;
    let byte_list = format!("{:?}", &WRAPPED[..]);
    let lower_hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let upper_hex: String = bytes.iter().map(|byte| format!("{byte:02X}")).collect();
    for marker in [&base64, &lower_hex, &upper_hex, &byte_list, "192, 255, 238"] {
        assert!(!debug.contains(marker), "{marker} in {debug}");
    }
    assert!(debug.contains("DecryptOnly"), "{debug}");
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

    fn apply(self, record: &mut KeyringRecord, key_id: KeyId) -> KeyringResult<()> {
        let now = Timestamp::now();
        match self {
            Operation::MarkCompromised => record
                .mark_compromised(key_id, Compromise::new(now, None), None, now)
                .map(|_| ()),
            Operation::Retire => record.retire(key_id, now),
            Operation::Reinstate => record.reinstate(key_id, now),
            Operation::Destroy => record.destroy(key_id, now),
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
            let mut record = parse(&document(vec![version(1, state, compromised)?]))?;
            operation.apply(&mut record, key_id(1)?)?;
            let version = record.version(key_id(1)?).ok_or("version 1 is gone")?;
            assert_eq!(
                (version.state(), version.compromised().is_some()),
                (expected_state, expected_compromised),
                "{operation:?} on {state}, compromised {compromised}"
            );
            if compromised {
                assert_eq!(
                    version.compromised().map(Compromise::at),
                    Some(timestamp(COMPROMISED)?),
                    "the flag keeps its time"
                );
            }
            assert_eq!(
                record
                    .version(key_id(1)?)
                    .map(KeyVersion::wrapped_dek)
                    .map(|dek| dek.is_some()),
                Some(expected_state != KeyVersionState::Destroyed)
            );
            record.validated()?;
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
            let mut record = parse(&document(vec![version(1, state, compromised)?]))?;
            let before = record.to_json()?;
            assert!(
                matches!(
                    operation.apply(&mut record, key_id(1)?),
                    Err(KeyringError::InvalidTransition(error))
                        if error.transition == operation.transition() && error.key_id == key_id(1)?
                ),
                "{operation:?} on {state}, compromised {compromised}"
            );
            assert_eq!(
                record.to_json()?,
                before,
                "a refused transition changes nothing"
            );
        }
    }
    Ok(())
}

#[test]
fn an_unknown_key_id_is_no_transition() -> KeyringResult<()> {
    let mut record = parse(&rotated()?)?;
    assert!(matches!(
        record.retire(key_id(9)?, Timestamp::now()),
        Err(KeyringError::KeyVersionUnknown(error)) if error.key_id == key_id(9)?
    ));
    Ok(())
}

fn new_version(algorithm: KeyAlgorithm) -> KeyringResult<NewVersion> {
    Ok(NewVersion {
        algorithm,
        dek: wrapped_dek()?,
    })
}

#[test]
fn rotation_takes_the_next_key_id_of_its_purpose() -> KeyringResult<()> {
    let mut record = parse(&rotated()?)?;
    let now = Timestamp::now();
    let rotation = record.rotate(
        new_version(KeyAlgorithm::Randomized(AeadAlgorithm::Aes256Gcm))?,
        now,
    )?;
    assert_eq!(
        rotation,
        Rotation {
            purpose: Purpose::Randomized,
            previous: Some(key_id(2)?),
            current: key_id(3)?,
        }
    );
    let rotation = record.rotate(
        new_version(KeyAlgorithm::Deterministic(
            DeterministicAlgorithm::Aes256Siv,
        ))?,
        now,
    )?;
    assert_eq!(rotation.current, key_id(0x8000_0002)?);
    assert_eq!(
        record.version(key_id(2)?).map(KeyVersion::state),
        Some(KeyVersionState::DecryptOnly)
    );
    assert_eq!(record.updated_at(), now);
    record.validated()?;
    Ok(())
}

#[test]
fn rotation_without_an_active_version_creates_one() -> KeyringResult<()> {
    let mut record = parse(&document(vec![version(1, "decrypt_only", true)?]))?;
    let rotation = record.rotate(
        new_version(KeyAlgorithm::Randomized(AeadAlgorithm::Aes256Gcm))?,
        Timestamp::now(),
    )?;
    assert_eq!((rotation.previous, rotation.current), (None, key_id(2)?));
    Ok(())
}

#[test]
fn compromising_the_active_version_rotates_in_the_same_change() -> KeyringResult<()> {
    let now = Timestamp::now();
    let replacement = new_version(KeyAlgorithm::Randomized(AeadAlgorithm::Aes256Gcm))?;
    let mut record = parse(&rotated()?)?;
    let rotation = record.mark_compromised(
        key_id(2)?,
        Compromise::new(now, Some("leaked".to_string())),
        Some(replacement),
        now,
    )?;
    assert_eq!(
        rotation.map(|rotation| (rotation.previous, rotation.current)),
        Some((Some(key_id(2)?), key_id(3)?))
    );
    assert_eq!(
        record.active(Purpose::Randomized).map(KeyVersion::key_id),
        Some(key_id(3)?)
    );

    let mut flag_alone = parse(&rotated()?)?;
    let rotation =
        flag_alone.mark_compromised(key_id(2)?, Compromise::new(now, None), None, now)?;
    assert_eq!(rotation, None);
    assert!(flag_alone.active(Purpose::Randomized).is_none());
    flag_alone.validated()?;
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
            RegressionRule::VersionMissing(key_id(1)?),
        ),
        (
            |next| next["versions"][1]["created_at"] = json!(ROTATED),
            RegressionRule::VersionAltered(key_id(2)?),
        ),
        (
            |next| next["versions"][0]["compromised"] = Value::Null,
            RegressionRule::CompromiseCleared(key_id(1)?),
        ),
        (
            |next| next["versions"][0]["compromised"]["at"] = json!(ROTATED),
            RegressionRule::CompromiseAltered(key_id(1)?),
        ),
        (
            |next| {
                next["versions"][1]["state"] = json!("decrypt_only");
                next["versions"][2]["state"] = json!("active");
            },
            RegressionRule::StateReverted(key_id(3)?),
        ),
        (
            |next| {
                next["versions"][3]["state"] = json!("retired");
                next["versions"][3]["wrapped_dek"] =
                    json!(STANDARD.encode([0xFF, 0x01, 0x00, 0x2A]));
            },
            RegressionRule::StateReverted(key_id(4)?),
        ),
    ];
    let held_record = parse(&held()?)?;
    for (change, rule) in cases {
        let mut next = held()?;
        change(&mut next);
        let next = parse(&next)?;
        assert_eq!(held_record.check_successor(&next), Err(rule));
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
    assert_eq!(held_record.check_successor(&parse(&next)?), Ok(()));
    assert_eq!(held_record.check_successor(&held_record), Ok(()));
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
    assert_eq!(held_record.withdrawn_deks(&next).count(), 2);
    assert_eq!(held_record.withdrawn_deks(&held_record).count(), 0);
    Ok(())
}

#[test]
fn a_rewrapped_key_withdraws_the_bytes_it_replaces() -> TestResult {
    let held_record = parse(&held()?)?;
    let mut next = held()?;
    next["versions"][1]["wrapped_dek"] = json!(STANDARD.encode(
        EncryptedDataEncryptionKey::new(vec![0x0B, 0xAD], None).to_bytes()?
    ));
    let next = parse(&next)?;
    let withdrawn: Vec<_> = held_record.withdrawn_deks(&next).collect();
    assert_eq!(withdrawn, [&wrapped_dek()?]);
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
