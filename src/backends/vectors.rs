//! The published test vectors of the signature and MAC operations, run on every enabled backend:
//! Wycheproof, RFC 8032 and RFC 4231. The public API signs and verifies only DSSE pre-images, so
//! the vectors reach the crate-private backend operations and the DER conversion directly. The
//! files are in `tests/vectors/`; the five Wycheproof files are those of
//! `C2SP/wycheproof` `testvectors_v1` at commit `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::Deserialize;

#[cfg(feature = "aws-lc-rs")]
use super::AwsLc;
#[cfg(feature = "ring")]
use super::Ring;
#[cfg(feature = "rustcrypto")]
use super::RustCrypto;
use crate::backends::AeadBackend;
use crate::formats::PublicKeyFormat;
use crate::signing::{RawSignature, SigningAlgorithm, SigningInput, VerifyingKey};

const WYCHEPROOF_ECDSA_P1363: &str =
    include_str!("../../tests/vectors/ecdsa_secp256r1_sha256_p1363_test.json");
const WYCHEPROOF_ECDSA_DER: &str =
    include_str!("../../tests/vectors/ecdsa_secp256r1_sha256_test.json");
const WYCHEPROOF_ED25519: &str = include_str!("../../tests/vectors/ed25519_test.json");
const WYCHEPROOF_HMAC_SHA256: &str = include_str!("../../tests/vectors/hmac_sha256_test.json");
const WYCHEPROOF_HMAC_SHA512: &str = include_str!("../../tests/vectors/hmac_sha512_test.json");
const RFC_8032_ED25519: &str = include_str!("../../tests/vectors/rfc8032_ed25519.json");
const RFC_4231_HMAC: &str = include_str!("../../tests/vectors/rfc4231_hmac.json");

/// Wycheproof flags of a signature whose DER encoding is wrong. The conversion at the provider
/// refuses all of them, whichever the verification would have said.
const DER_ENCODING_FLAGS: [&str; 4] = [
    "InvalidEncoding",
    "BerEncodedSignature",
    "MissingZero",
    "InvalidTypesInSignature",
];

/// HMAC of a message under a key.
type MacFn = fn(&[u8], &[u8]) -> Option<Vec<u8>>;
/// The Ed25519 signature of a message under a seed and its public key.
type Ed25519SignFn = fn(&[u8], &[u8], &[u8]) -> Option<Vec<u8>>;

/// The operations of one backend, so that a test iterates over the enabled backends without being
/// generic over them.
struct Backend {
    name: &'static str,
    /// Whether the backend takes `public_key` and verifies the 64-byte `signature` over `message`.
    verify: fn(SigningAlgorithm, &[u8], &[u8], &[u8]) -> bool,
    hmac_sha256: MacFn,
    hmac_sha512: MacFn,
    sha256: fn(&[u8]) -> Option<Vec<u8>>,
    ed25519_public_key: fn(&[u8]) -> Option<Vec<u8>>,
    ed25519_sign: Ed25519SignFn,
}

fn backend<B: AeadBackend>() -> Backend {
    Backend {
        name: B::NAME,
        verify: accepts::<B>,
        hmac_sha256: |key, message| B::hmac_sha256(key, message).ok().map(|tag| tag.to_vec()),
        hmac_sha512: |key, message| {
            let mut tag = [0; 64];
            B::hmac_sha512(key, &[message], &mut tag)
                .ok()
                .map(|()| tag.to_vec())
        },
        sha256: |message| B::sha256(message).ok().map(|digest| digest.to_vec()),
        ed25519_public_key: |seed| B::ed25519_public_key(seed).ok().map(|key| key.to_vec()),
        ed25519_sign: |seed, public_key, message| {
            B::sign(
                seed,
                public_key,
                &SigningInput::Ed25519 { pre_image: message },
            )
            .ok()
        },
    }
}

/// The backend operations take the lengths of the algorithm and leave the check to the caller, so a
/// signature or key of another length is refused here, as the verifier refuses it. The key is
/// checked before it verifies anything, as `Verifier::new` does.
fn accepts<B: AeadBackend>(
    algorithm: SigningAlgorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    signature.len() == algorithm.signature_len()
        && public_key.len() == algorithm.public_key_len()
        && B::check_verifying_key(algorithm, public_key).is_ok()
        && B::verify(algorithm, public_key, message, signature).is_ok()
}

fn backends() -> Vec<Backend> {
    Vec::from([
        #[cfg(feature = "ring")]
        backend::<Ring>(),
        #[cfg(feature = "aws-lc-rs")]
        backend::<AwsLc>(),
        #[cfg(feature = "rustcrypto")]
        backend::<RustCrypto>(),
    ])
}

fn parse<T: DeserializeOwned>(json: &str) -> T {
    serde_json::from_str(json).expect("a vector file parses")
}

fn decode(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("a vector is hex")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Expected {
    Valid,
    Invalid,
    Acceptable,
}

impl Expected {
    /// Whether accepting or refusing a case contradicts the expectation; an acceptable case
    /// contradicts neither.
    fn contradicted_by(self, accepted: bool) -> bool {
        match self {
            Expected::Valid => !accepted,
            Expected::Invalid => accepted,
            Expected::Acceptable => false,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Suite<G> {
    test_groups: Vec<G>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureGroup {
    public_key: SignatureKey,
    tests: Vec<SignatureCase>,
}

#[derive(Deserialize)]
struct SignatureKey {
    /// The uncompressed point of a P-256 key, or the 32 bytes of an Ed25519 key.
    #[serde(alias = "uncompressed", alias = "pk")]
    raw: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureCase {
    tc_id: u32,
    flags: Vec<String>,
    msg: String,
    sig: String,
    result: Expected,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MacGroup {
    tests: Vec<MacCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MacCase {
    tc_id: u32,
    key: String,
    msg: String,
    tag: String,
    result: Expected,
}

/// Runs every case of a Wycheproof signature file on every backend. `raw_signature` turns the
/// file's signature into the 64 bytes the backend takes, or refuses it as the provider's
/// conversion does. Returns the cases whose outcome contradicts the file's expectation; the
/// `acceptable` ones are printed, one line per backend.
fn signature_failures(
    json: &str,
    algorithm: SigningAlgorithm,
    raw_signature: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> Vec<String> {
    let suite: Suite<SignatureGroup> = parse(json);
    let mut failures = Vec::new();
    for backend in backends() {
        let mut accepted_acceptable: BTreeMap<String, usize> = BTreeMap::new();
        let mut refused_acceptable = Vec::new();
        for group in &suite.test_groups {
            let public_key = decode(&group.public_key.raw);
            for case in &group.tests {
                let accepted = raw_signature(&decode(&case.sig)).is_some_and(|signature| {
                    (backend.verify)(algorithm, &public_key, &decode(&case.msg), &signature)
                });
                if case.result.contradicted_by(accepted) {
                    failures.push(format!(
                        "{} tcId {} ({:?}, {:?}) was {}",
                        backend.name,
                        case.tc_id,
                        case.result,
                        case.flags,
                        if accepted { "accepted" } else { "refused" },
                    ));
                }
                if case.result == Expected::Acceptable {
                    if accepted {
                        *accepted_acceptable.entry(case.flags.join("+")).or_default() += 1;
                    } else {
                        refused_acceptable.push(format!("{} {}", case.tc_id, case.flags.join("+")));
                    }
                }
            }
        }
        if !accepted_acceptable.is_empty() || !refused_acceptable.is_empty() {
            eprintln!(
                "{} {algorithm}, acceptable cases: accepted {accepted_acceptable:?}; refused [{}]",
                backend.name,
                refused_acceptable.join(", "),
            );
        }
    }
    failures
}

fn mac_failures(json: &str, mac: impl Fn(&Backend) -> MacFn) -> Vec<String> {
    let suite: Suite<MacGroup> = parse(json);
    let mut failures = Vec::new();
    for backend in backends() {
        let mac = mac(&backend);
        for case in suite.test_groups.iter().flat_map(|group| &group.tests) {
            let tag = decode(&case.tag);
            let computed =
                mac(&decode(&case.key), &decode(&case.msg)).expect("a backend computes a MAC");
            // A group's tag may be truncated: it matches when it is the start of the full MAC.
            let accepted = computed.starts_with(&tag);
            if case.result.contradicted_by(accepted) {
                failures.push(format!(
                    "{} tcId {} ({:?}) was {}",
                    backend.name,
                    case.tc_id,
                    case.result,
                    if accepted { "accepted" } else { "refused" },
                ));
            }
        }
    }
    failures
}

fn assert_no_failures(failures: &[String]) {
    assert!(
        failures.is_empty(),
        "{} failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn every_wycheproof_p256_p1363_case_verifies_as_expected_on_every_backend() {
    let failures = signature_failures(
        WYCHEPROOF_ECDSA_P1363,
        SigningAlgorithm::EcdsaP256Sha256,
        |signature| Some(signature.to_vec()),
    );

    assert_no_failures(&failures);
}

#[test]
fn every_wycheproof_p256_der_case_converts_and_verifies_as_expected_on_every_backend() {
    let failures = signature_failures(
        WYCHEPROOF_ECDSA_DER,
        SigningAlgorithm::EcdsaP256Sha256,
        |der| {
            RawSignature::from_ecdsa_p256_der(der)
                .ok()
                .map(RawSignature::into_value)
        },
    );

    assert_no_failures(&failures);
}

#[test]
fn every_wycheproof_der_encoding_flaw_is_refused_as_signature_encoding() {
    let suite: Suite<SignatureGroup> = parse(WYCHEPROOF_ECDSA_DER);
    let mut failures = Vec::new();
    for case in suite.test_groups.iter().flat_map(|group| &group.tests) {
        let result = RawSignature::from_ecdsa_p256_der(&decode(&case.sig));
        let flawed = case
            .flags
            .iter()
            .any(|flag| DER_ENCODING_FLAGS.contains(&flag.as_str()));
        let contradicted = match (&result, case.result) {
            (Ok(_), Expected::Invalid) => flawed,
            (Err(error), Expected::Invalid) => flawed && error.code() != "SIGNATURE_ENCODING",
            (Err(_), Expected::Valid) => true,
            (Ok(_), Expected::Valid) | (_, Expected::Acceptable) => false,
        };
        if contradicted {
            failures.push(format!(
                "tcId {} ({:?}, {:?}) converted to {:?}",
                case.tc_id, case.result, case.flags, result
            ));
        }
    }

    assert_no_failures(&failures);
}

#[test]
fn every_wycheproof_ed25519_case_verifies_as_expected_on_every_backend() {
    let failures = signature_failures(WYCHEPROOF_ED25519, SigningAlgorithm::Ed25519, |signature| {
        Some(signature.to_vec())
    });

    assert_no_failures(&failures);
}

#[test]
fn every_wycheproof_small_order_public_key_is_refused_when_a_verifying_key_is_built() {
    let suite: Suite<SignatureGroup> = parse(WYCHEPROOF_ED25519);
    let mut small_order = 0;
    let mut failures = Vec::new();
    for group in &suite.test_groups {
        let public_key = decode(&group.public_key.raw);
        for case in &group.tests {
            if !case.flags.iter().any(|flag| flag == "SmallOrderPublicKey") {
                continue;
            }
            small_order += 1;
            let result = VerifyingKey::from_bytes(
                SigningAlgorithm::Ed25519,
                &public_key,
                PublicKeyFormat::Raw,
            );
            if !matches!(&result, Err(error) if error.code() == "INVALID_PUBLIC_KEY") {
                failures.push(format!("tcId {} was built as {result:?}", case.tc_id));
            }
        }
    }

    assert_eq!(small_order, 8);
    assert_no_failures(&failures);
}

#[test]
fn every_wycheproof_hmac_sha256_case_matches_as_expected_on_every_backend() {
    let failures = mac_failures(WYCHEPROOF_HMAC_SHA256, |backend| backend.hmac_sha256);

    assert_no_failures(&failures);
}

#[test]
fn every_wycheproof_hmac_sha512_case_matches_as_expected_on_every_backend() {
    let failures = mac_failures(WYCHEPROOF_HMAC_SHA512, |backend| backend.hmac_sha512);

    assert_no_failures(&failures);
}

#[derive(Deserialize)]
struct Rfc8032Suite {
    tests: Vec<Rfc8032Case>,
}

#[derive(Deserialize)]
struct Rfc8032Case {
    name: String,
    secret_key: String,
    public_key: String,
    msg: String,
    signature: String,
}

#[test]
fn rfc_8032_ed25519_keys_signatures_and_verification_hold_on_every_backend() {
    let suite: Rfc8032Suite = parse(RFC_8032_ED25519);
    assert_eq!(suite.tests.len(), 5);
    let mut failures = Vec::new();
    for backend in backends() {
        for case in &suite.tests {
            let (seed, public_key) = (decode(&case.secret_key), decode(&case.public_key));
            let (message, signature) = (decode(&case.msg), decode(&case.signature));
            let mut other_message = message.clone();
            other_message.push(0);
            let checks = [
                (
                    "public key",
                    (backend.ed25519_public_key)(&seed).as_deref() == Some(public_key.as_slice()),
                ),
                (
                    "signature",
                    (backend.ed25519_sign)(&seed, &public_key, &message).as_deref()
                        == Some(signature.as_slice()),
                ),
                (
                    "verification",
                    (backend.verify)(SigningAlgorithm::Ed25519, &public_key, &message, &signature),
                ),
                (
                    "refusal of another message",
                    !(backend.verify)(
                        SigningAlgorithm::Ed25519,
                        &public_key,
                        &other_message,
                        &signature,
                    ),
                ),
            ];
            for (check, holds) in checks {
                if !holds {
                    failures.push(format!("{} test {}: {check}", backend.name, case.name));
                }
            }
        }
    }

    assert_no_failures(&failures);
}

#[derive(Deserialize)]
struct Rfc4231Suite {
    tests: Vec<Rfc4231Case>,
}

#[derive(Deserialize)]
struct Rfc4231Case {
    case: u32,
    key: String,
    data: String,
    hmac_sha256: String,
    hmac_sha512: String,
}

#[test]
fn rfc_4231_hmac_cases_match_on_every_backend() {
    let suite: Rfc4231Suite = parse(RFC_4231_HMAC);
    assert_eq!(suite.tests.len(), 7);
    let mut failures = Vec::new();
    for backend in backends() {
        for case in &suite.tests {
            let (key, data) = (decode(&case.key), decode(&case.data));
            for (algorithm, mac, expected) in [
                ("HMAC-SHA-256", backend.hmac_sha256, &case.hmac_sha256),
                ("HMAC-SHA-512", backend.hmac_sha512, &case.hmac_sha512),
            ] {
                // Test case 5 publishes the first 128 bits only.
                let matches = mac(&key, &data)
                    .is_some_and(|computed| computed.starts_with(&decode(expected)));
                if !matches {
                    failures.push(format!(
                        "{} test case {}: {algorithm}",
                        backend.name, case.case
                    ));
                }
            }
        }
    }

    assert_no_failures(&failures);
}

#[test]
fn sha256_matches_the_published_digests_on_every_backend() {
    let backends = backends();
    for (message, digest) in [
        (
            b"".as_slice(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc".as_slice(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
    ] {
        for backend in &backends {
            assert_eq!(
                (backend.sha256)(message).as_deref(),
                Some(decode(digest).as_slice()),
                "{}",
                backend.name
            );
        }
    }
}
