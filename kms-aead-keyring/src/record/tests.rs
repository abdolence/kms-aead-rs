use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};

use super::*;
use crate::errors::{RecordInvalidError, RecordInvalidReason};
use crate::test_support::{TestResult, TENANT};

const CREATED: &str = "2026-01-10T09:00:00Z";
const ROTATED: &str = "2026-04-10T09:00:00Z";
pub(super) const COMPROMISED: &str = "2026-05-01T12:00:00Z";
/// The encrypted bytes of every fixture version: distinctive, so that a test can look for them.
pub(super) const ENCRYPTED_DEK: [u8; 6] = [0xC0, 0xFF, 0xEE, 0xC0, 0xFF, 0xEE];
/// [`ENCRYPTED_DEK`] in standard base64, as the record stores it.
const ENCRYPTED_DEK_BASE64: &str = "wP/uwP/u";
/// The KEK version of every fixture version's encrypted DEK.
const KEK_VERSION: &str = "4";

/// A version as the stored form writes it, with an encrypted DEK and its KEK version unless it is
/// destroyed, and a seal range that fits its state in a [`document`] at epoch 2: open from 2 while
/// active, from 1 to 2 once decrypt-only or retired, and none while pending or once destroyed.
pub(super) fn version(key_id: u32, state: &str, compromised: bool) -> KeyringResult<Value> {
    let algorithm = if key_id >> 31 == 1 {
        "aes-256-siv"
    } else {
        "aes-256-gcm"
    };
    let (encrypted_dek, kek_version) = match state {
        "destroyed" => (Value::Null, Value::Null),
        _ => (json!(ENCRYPTED_DEK_BASE64), json!(KEK_VERSION)),
    };
    let compromised = match compromised {
        true => json!({ "at": COMPROMISED, "note": "laptop lost" }),
        false => Value::Null,
    };
    let seal_epochs = match state {
        "active" => json!({ "start": 2, "end": null }),
        "decrypt_only" | "retired" => json!({ "start": 1, "end": 2 }),
        _ => Value::Null,
    };
    Ok(json!({
        "key_id": key_id,
        "algorithm": algorithm,
        "state": state,
        "compromised": compromised,
        "seal_epochs": seal_epochs,
        "created_at": CREATED,
        "state_changed_at": ROTATED,
        "encrypted_dek": encrypted_dek,
        "kek_version": kek_version,
    }))
}

pub(super) fn document(versions: Vec<Value>) -> Value {
    json!({
        "schema": 1,
        "id": TENANT.as_str(),
        "kek": { "provider": "gcp", "key": "projects/p/locations/europe-west1/keyRings/app/cryptoKeys/keyring-kek" },
        "algorithms": {
            "randomized": "aes-256-gcm",
            "deterministic": "aes-256-siv",
            "beacon": "hmac-sha256",
        },
        "seal_epoch": 2,
        "versions": versions,
        "created_at": CREATED,
        "updated_at": ROTATED,
    })
}

pub(super) fn parse(document: &Value) -> KeyringResult<KeyringRecord> {
    KeyringRecord::from_json(&TENANT, document.to_string().as_bytes())
}

/// The reason `document` is refused for, or `None` when it parses.
fn refusal(document: &Value) -> Option<RecordInvalidReason> {
    match parse(document) {
        Err(KeyringError::RecordInvalid(RecordInvalidError { reason, .. })) => Some(reason),
        _ => None,
    }
}

/// A rotated keyring: randomised 1 decrypts only, 2 is active, deterministic 2147483649 is
/// active.
pub(super) fn rotated() -> KeyringResult<Value> {
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
        reparsed.active(Purpose::Randomized).map(KeyVersion::id),
        Some(KeyId::new(2))
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
fn two_pending_versions_of_one_purpose_are_rejected() -> KeyringResult<()> {
    let document = document(vec![
        version(1, "active", false)?,
        version(2, "pending", false)?,
        version(3, "pending", false)?,
    ]);
    assert_eq!(
        refusal(&document),
        Some(RecordInvalidReason::TwoPendingVersions(Purpose::Randomized))
    );
    Ok(())
}

#[test]
fn a_pending_compromised_version_is_rejected() -> KeyringResult<()> {
    let document = document(vec![
        version(1, "active", false)?,
        version(2, "pending", true)?,
    ]);
    assert_eq!(
        refusal(&document),
        Some(RecordInvalidReason::CompromisedPending(KeyId::new(2)))
    );
    Ok(())
}

#[test]
fn an_active_compromised_version_is_rejected() -> KeyringResult<()> {
    let document = document(vec![version(1, "active", true)?]);
    assert_eq!(
        refusal(&document),
        Some(RecordInvalidReason::CompromisedActive(KeyId::new(1)))
    );
    Ok(())
}

#[test]
fn a_destroyed_version_with_material_is_rejected() -> KeyringResult<()> {
    for (field, value) in [
        ("encrypted_dek", json!(ENCRYPTED_DEK_BASE64)),
        ("kek_version", json!(KEK_VERSION)),
    ] {
        let mut destroyed = version(1, "destroyed", false)?;
        destroyed[field] = value;
        assert_eq!(
            refusal(&document(vec![destroyed, version(2, "active", false)?])),
            Some(RecordInvalidReason::DestroyedWithMaterial(KeyId::new(1))),
            "{field}"
        );
    }
    Ok(())
}

#[test]
fn a_version_without_material_is_rejected() -> KeyringResult<()> {
    for kek_version in [Value::Null, json!(KEK_VERSION)] {
        let mut retired = version(1, "retired", false)?;
        retired["encrypted_dek"] = Value::Null;
        retired["kek_version"] = kek_version.clone();
        assert_eq!(
            refusal(&document(vec![retired, version(2, "active", false)?])),
            Some(RecordInvalidReason::MissingMaterial(KeyId::new(1))),
            "{kek_version}"
        );
    }
    Ok(())
}

#[test]
fn a_key_id_of_the_wrong_purpose_is_rejected() -> KeyringResult<()> {
    let mut deterministic_id = version(1, "active", false)?;
    deterministic_id["key_id"] = json!(0x8000_0001u32);
    assert_eq!(
        refusal(&document(vec![deterministic_id])),
        Some(RecordInvalidReason::PurposeMismatch(KeyId::new(
            0x8000_0001
        )))
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
        Some(RecordInvalidReason::DuplicateKeyId(KeyId::new(1)))
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
        Some(RecordInvalidReason::OrdinalOrder(KeyId::new(1)))
    );
    Ok(())
}

#[test]
fn an_encrypted_dek_that_does_not_parse_is_rejected() -> KeyringResult<()> {
    for encrypted_dek in ["not base64!", ""] {
        let mut active = version(1, "active", false)?;
        active["encrypted_dek"] = json!(encrypted_dek);
        assert_eq!(
            refusal(&document(vec![active])),
            Some(RecordInvalidReason::MalformedEncryptedDek(KeyId::new(1)))
        );
    }
    Ok(())
}

#[test]
fn a_kek_version_that_does_not_parse_is_rejected() -> KeyringResult<()> {
    let mut active = version(1, "active", false)?;
    active["kek_version"] = json!("4/5");
    assert_eq!(
        refusal(&document(vec![active])),
        Some(RecordInvalidReason::MalformedKekVersion(KeyId::new(1)))
    );
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
        Some(RecordInvalidReason::PurposeMismatch(KeyId::new(1)))
    );

    let mut state = version(1, "active", false)?;
    state["state"] = json!("dormant");
    assert_eq!(
        refusal(&document(vec![state])),
        Some(RecordInvalidReason::UnknownState(KeyId::new(1)))
    );
    Ok(())
}

#[test]
fn a_seal_epoch_of_zero_is_rejected() -> KeyringResult<()> {
    let mut envelope_epoch = rotated()?;
    envelope_epoch["seal_epoch"] = json!(0);
    assert_eq!(
        refusal(&envelope_epoch),
        Some(RecordInvalidReason::SealEpochOutOfRange)
    );
    Ok(())
}

#[test]
fn a_seal_range_that_does_not_fit_its_state_or_the_epoch_is_rejected() -> KeyringResult<()> {
    let open_from_one = json!({ "start": 1, "end": null });
    for (state, seal_epochs) in [
        ("pending", open_from_one.clone()),
        ("active", Value::Null),
        ("active", json!({ "start": 1, "end": 2 })),
        ("decrypt_only", Value::Null),
        ("retired", Value::Null),
        ("decrypt_only", json!({ "start": 0, "end": 2 })),
        ("decrypt_only", json!({ "start": 2, "end": 2 })),
        ("decrypt_only", json!({ "start": 1, "end": 3 })),
        ("active", json!({ "start": 3, "end": null })),
    ] {
        let mut stored = version(1, state, false)?;
        stored["seal_epochs"] = seal_epochs.clone();
        assert_eq!(
            refusal(&document(vec![stored])),
            Some(RecordInvalidReason::SealRangeInvalid(KeyId::new(1))),
            "{state} with {seal_epochs}"
        );
    }
    let mut destroyed = version(1, "destroyed", false)?;
    destroyed["seal_epochs"] = open_from_one;
    assert_eq!(refusal(&document(vec![destroyed])), None);
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
    document["versions"][0]["key_id"] = json!(ENCRYPTED_DEK_BASE64);
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
        assert!(!text.contains(ENCRYPTED_DEK_BASE64), "{text}");
    }
    Ok(())
}

#[test]
fn record_debug_carries_no_encrypted_dek() -> TestResult {
    let record = parse(&rotated()?)?;
    let debug = format!("{record:?}");
    let byte_list = format!("{:?}", &ENCRYPTED_DEK[..]);
    let lower_hex: String = ENCRYPTED_DEK
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let upper_hex: String = ENCRYPTED_DEK
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect();
    for marker in [
        ENCRYPTED_DEK_BASE64,
        &lower_hex,
        &upper_hex,
        &byte_list,
        "192, 255, 238",
    ] {
        assert!(!debug.contains(marker), "{marker} in {debug}");
    }
    Ok(())
}

/// The held record of the regression cases, at epoch 3: randomised 1 compromised and
/// decrypt-only, 2 active, 3 retired, 4 destroyed, 5 pending.
fn held() -> KeyringResult<Value> {
    let mut held = document(vec![
        version(1, "decrypt_only", true)?,
        version(2, "active", false)?,
        version(3, "retired", false)?,
        version(4, "destroyed", false)?,
        version(5, "pending", false)?,
    ]);
    held["seal_epoch"] = json!(3);
    Ok(held)
}

#[test]
fn a_regressed_record_is_refused() -> TestResult {
    type Change = fn(&mut Value);
    let cases: [(Change, RegressionRule); 14] = [
        (
            |next| {
                if let Some(versions) = next["versions"].as_array_mut() {
                    versions.remove(0);
                }
            },
            RegressionRule::VersionMissing(KeyId::new(1)),
        ),
        (
            |next| next["versions"][1]["created_at"] = json!(ROTATED),
            RegressionRule::VersionAltered(KeyId::new(2)),
        ),
        (
            |next| next["versions"][0]["compromised"] = Value::Null,
            RegressionRule::CompromiseCleared(KeyId::new(1)),
        ),
        (
            |next| next["versions"][0]["compromised"]["at"] = json!(ROTATED),
            RegressionRule::CompromiseAltered(KeyId::new(1)),
        ),
        (
            |next| {
                next["versions"][1]["state"] = json!("decrypt_only");
                next["versions"][2]["state"] = json!("active");
                next["versions"][2]["seal_epochs"]["end"] = Value::Null;
            },
            RegressionRule::StateReverted(KeyId::new(3)),
        ),
        (
            |next| {
                next["versions"][3]["state"] = json!("retired");
                next["versions"][3]["seal_epochs"] = json!({ "start": 1, "end": 2 });
                next["versions"][3]["encrypted_dek"] =
                    json!(STANDARD.encode([0xFF, 0x01, 0x00, 0x2A]));
            },
            RegressionRule::StateReverted(KeyId::new(4)),
        ),
        (
            |next| {
                next["versions"][1]["state"] = json!("pending");
                next["versions"][1]["seal_epochs"] = Value::Null;
                next["versions"][4]["state"] = json!("active");
                next["versions"][4]["seal_epochs"] = json!({ "start": 3, "end": null });
            },
            RegressionRule::StateReverted(KeyId::new(2)),
        ),
        (
            |next| {
                next["versions"][1]["state"] = json!("decrypt_only");
                next["versions"][4]["state"] = json!("active");
                next["versions"][4]["seal_epochs"] = json!({ "start": 3, "end": null });
                next["versions"][2]["state"] = json!("pending");
                next["versions"][2]["seal_epochs"] = Value::Null;
            },
            RegressionRule::StateReverted(KeyId::new(3)),
        ),
        (
            |next| next["versions"][1]["seal_epochs"]["start"] = json!(1),
            RegressionRule::SealRangeReverted(KeyId::new(2)),
        ),
        (
            |next| next["versions"][0]["seal_epochs"]["end"] = json!(3),
            RegressionRule::SealRangeReverted(KeyId::new(1)),
        ),
        (
            |next| {
                next["versions"][2]["state"] = json!("destroyed");
                next["versions"][2]["seal_epochs"] = Value::Null;
                next["versions"][2]["encrypted_dek"] = Value::Null;
                next["versions"][2]["kek_version"] = Value::Null;
            },
            RegressionRule::SealRangeReverted(KeyId::new(3)),
        ),
        (
            |next| {
                next["versions"][1]["state"] = json!("decrypt_only");
                next["versions"][1]["seal_epochs"]["end"] = json!(3);
            },
            RegressionRule::SealRangeReverted(KeyId::new(2)),
        ),
        (
            |next| {
                next["seal_epoch"] = json!(4);
                next["versions"][1]["state"] = json!("decrypt_only");
                next["versions"][1]["seal_epochs"]["end"] = json!(4);
                next["versions"][4]["state"] = json!("active");
                next["versions"][4]["seal_epochs"] = json!({ "start": 3, "end": null });
            },
            RegressionRule::SealRangeReverted(KeyId::new(5)),
        ),
        (
            |next| next["seal_epoch"] = json!(2),
            RegressionRule::SealEpochReverted,
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
    next["seal_epoch"] = json!(4);
    next["versions"][0]["state"] = json!("destroyed");
    next["versions"][0]["encrypted_dek"] = Value::Null;
    next["versions"][0]["kek_version"] = Value::Null;
    next["versions"][1]["state"] = json!("retired");
    next["versions"][1]["seal_epochs"]["end"] = json!(4);
    next["versions"][2]["state"] = json!("decrypt_only");
    next["versions"][2]["compromised"] = json!({ "at": COMPROMISED, "note": null });
    next["versions"][4]["state"] = json!("active");
    next["versions"][4]["seal_epochs"] = json!({ "start": 4, "end": null });
    if let Some(versions) = next["versions"].as_array_mut() {
        versions.push(version(6, "pending", false)?);
    }
    assert_eq!(check_successor(&held_record, &parse(&next)?), Ok(()));
    assert_eq!(check_successor(&held_record, &held_record), Ok(()));

    let mut destroyed = held()?;
    destroyed["versions"][4]["state"] = json!("destroyed");
    destroyed["versions"][4]["encrypted_dek"] = Value::Null;
    destroyed["versions"][4]["kek_version"] = Value::Null;
    assert_eq!(check_successor(&held_record, &parse(&destroyed)?), Ok(()));
    let mut retired = held()?;
    retired["seal_epoch"] = json!(5);
    retired["versions"][1]["state"] = json!("decrypt_only");
    retired["versions"][1]["seal_epochs"]["end"] = json!(4);
    retired["versions"][4]["state"] = json!("retired");
    retired["versions"][4]["seal_epochs"] = json!({ "start": 4, "end": 5 });
    assert_eq!(check_successor(&held_record, &parse(&retired)?), Ok(()));
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
    next["versions"][4]["state"] = json!("destroyed");
    next["versions"][4]["encrypted_dek"] = Value::Null;
    next["versions"][4]["kek_version"] = Value::Null;
    if let Some(versions) = next["versions"].as_array_mut() {
        versions.push(version(6, "active", false)?);
    }
    let next = parse(&next)?;
    assert_eq!(withdrawn_deks(&held_record, &next).count(), 3);
    assert_eq!(withdrawn_deks(&held_record, &held_record).count(), 0);
    Ok(())
}

#[test]
fn a_reencrypted_key_withdraws_the_bytes_it_replaces() -> TestResult {
    let held_record = parse(&held()?)?;
    let mut next = held()?;
    next["versions"][1]["encrypted_dek"] = json!(STANDARD.encode([0x0B, 0xAD]));
    let next = parse(&next)?;
    let withdrawn: Vec<_> = withdrawn_deks(&held_record, &next).collect();
    assert_eq!(
        withdrawn,
        [(
            KeyId::new(2),
            &EncryptedDataEncryptionKey::new(ENCRYPTED_DEK.to_vec())
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
        KeyVersionState::Pending,
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
