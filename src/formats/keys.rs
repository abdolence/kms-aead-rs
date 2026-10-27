use secret_vault_value::SecretValue;

use crate::providers::local_key_source::decode_local_key_base64;

/// The encoding of a private key given to a local provider. The caller names it, and no loader
/// guesses it from the bytes.
///
/// Taken by `LocalSigningKey::from_secret`, `from_file` and `from_env`, and by
/// `LocalAsymmetricKek::from_secret`, `from_file` and `from_env`, which take both variants. The
/// text encoding is given as its bytes like the binary one, since a loader has bytes from a file,
/// a variable or a response: PEM is ASCII, and bytes that are not fail with the loader's format
/// error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PrivateKeyFormat {
    /// A PKCS#8 `PrivateKeyInfo` in DER: the binary form.
    Pkcs8Der,
    /// The same as a `PRIVATE KEY` PEM block, which `openssl genpkey` writes.
    Pkcs8Pem,
}

impl PrivateKeyFormat {
    /// The label of a PKCS#8 `PrivateKeyInfo` PEM block.
    pub(crate) const PEM_LABEL: &'static str = "PRIVATE KEY";

    /// The DER of the PKCS#8 `PrivateKeyInfo` that `content` holds in this format, or why it
    /// holds none, to follow "The PKCS#8 key from <origin>" in an error.
    pub(crate) fn pkcs8_der(self, content: SecretValue) -> Result<SecretValue, &'static str> {
        match self {
            PrivateKeyFormat::Pkcs8Der => Ok(content),
            PrivateKeyFormat::Pkcs8Pem => {
                let (label, der) = pem_rfc7468::decode_vec(content.ref_sensitive_value())
                    .map_err(|_| "is not a PEM block")?;
                let der = SecretValue::new(der);
                if label == Self::PEM_LABEL {
                    Ok(der)
                } else {
                    Err("is not a PRIVATE KEY PEM block")
                }
            }
        }
    }

    /// The key an environment variable holding `content` gives in this format: the DER of
    /// [`Pkcs8Der`](Self::Pkcs8Der) is held as its standard base64, since a variable holds text,
    /// and the PEM of [`Pkcs8Pem`](Self::Pkcs8Pem) as it is. `None` when the base64 does not
    /// decode.
    pub(crate) fn decode_env_text(self, content: SecretValue) -> Option<SecretValue> {
        match self {
            PrivateKeyFormat::Pkcs8Der => decode_local_key_base64(content),
            PrivateKeyFormat::Pkcs8Pem => Some(content),
        }
    }
}

/// The encoding of a public key given to a verifying type or an asymmetric KEK. The caller names
/// it, and no reader guesses it from the bytes.
///
/// Taken by `VerifyingKey::from_bytes` and `VerifyingKey::encode`, which take every variant, and by
/// `AsymmetricKekPublicKey::new` and `AsymmetricKekPublicKey::encode`, which take every variant but
/// [`Raw`](Self::Raw), since an RSA key has no raw form. A type that does not take a variant fails
/// with its own format error, `INVALID_PUBLIC_KEY` or `ASYMMETRIC_KEK_PUBLIC_KEY`, before it reads
/// a byte. The text encodings, [`SpkiPem`](Self::SpkiPem) and [`Jwk`](Self::Jwk), are given as
/// their bytes: PEM is ASCII and a JWK is UTF-8, and bytes that are not fail with the same error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PublicKeyFormat {
    /// The raw key of an algorithm the caller names, since raw bytes carry none: 32 bytes for
    /// Ed25519, the 65-byte uncompressed point for P-256.
    Raw,
    /// A SubjectPublicKeyInfo in DER.
    SpkiDer,
    /// A `PUBLIC KEY` PEM block.
    SpkiPem,
    /// One JSON Web Key, as UTF-8 JSON.
    Jwk,
}

impl PublicKeyFormat {
    /// The label of a SubjectPublicKeyInfo PEM block.
    pub(crate) const PEM_LABEL: &'static str = "PUBLIC KEY";

    /// The DER of the `PUBLIC KEY` PEM block `pem`, or why it holds none, to follow "The public
    /// key" in an error.
    pub(crate) fn spki_der_of_pem(pem: &[u8]) -> Result<Vec<u8>, String> {
        let (label, der) =
            pem_rfc7468::decode_vec(pem).map_err(|error| format!("is not PEM: {error}"))?;
        if label == Self::PEM_LABEL {
            Ok(der)
        } else {
            Err("is not a PUBLIC KEY PEM block, a SubjectPublicKeyInfo".to_string())
        }
    }
}

/// The encoding of a symmetric key given to a local provider: the KEK of
/// [`LocalKmsProvider`](crate::providers::LocalKmsProvider), which
/// [`LocalKek`](crate::providers::LocalKek) loads in every variant. There is no PEM variant, since
/// no standard gives a symmetric key a PEM label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SymmetricKeyFormat {
    /// The key bytes themselves.
    Raw,
    /// The standard base64 of the key bytes, trailing whitespace allowed.
    Base64,
    /// An `oct` JSON Web Key ([RFC 7518 section 6.4]), as UTF-8 JSON:
    /// `{"kty":"oct","k":"<base64url, no padding>"}`, with `k` the 32 key bytes. `alg` is optional
    /// and must be `A256GCM` or `A256KW` when present; `kid`, `use`, `key_ops` and any other
    /// member are ignored. A JWK of another `kty`, or a `k` in padded or standard base64, fails
    /// with the loader's source error.
    ///
    /// [RFC 7518 section 6.4]: https://www.rfc-editor.org/rfc/rfc7518#section-6.4
    Jwk,
}
