//! The key schedule and the chunk cipher of Cobblestone-256: HKDF-Expand with SHA-512 derives
//! a key, a base nonce and a commitment per value, and AES-256-GCM encrypts each chunk under the
//! key and the base nonce XORed with the chunk's index.

use std::marker::PhantomData;

use secret_vault_value::SecretValue;

use crate::backends::{AeadBackend, Failure, HmacSha512, Nonce, Tag};
use crate::AeadAlgorithm;

pub(crate) const STREAM_SALT_LEN: usize = 24;
pub(crate) const STREAM_KEY_COMMITMENT_LEN: usize = 32;
pub(crate) type Salt = [u8; STREAM_SALT_LEN];
pub(crate) type Commitment = [u8; STREAM_KEY_COMMITMENT_LEN];

/// The one algorithm of the format, of the DEK and of the derived key alike.
pub(crate) const CHUNK_ALGORITHM: AeadAlgorithm = AeadAlgorithm::Aes256Gcm;

const DERIVED_CHUNK_KEY_LEN: usize = 32;

/// The start of HKDF-Expand's `info`: the label of version 1 of c2sp.org/chunked-encryption,
/// the IANA name of the AEAD, and the zero byte that ends the name, so that the salt and the AAD
/// after it can never be read as part of the name.
const HKDF_INFO_PREFIX: &[u8] = b"c2sp.org/chunked-encryption@v1+AEAD_AES_256_GCM\0";

/// The key and the base nonce derived for one value, and the AES-256-GCM calls on its chunks.
pub(crate) struct ChunkCipher<B> {
    /// `[key: 32][base nonce: 12]`, zeroised on drop.
    derived: SecretValue,
    backend: PhantomData<fn() -> B>,
}

impl<B: AeadBackend> ChunkCipher<B> {
    /// The cipher of the value with `salt` and `aad` under `dek`, a 32-byte key, and the key
    /// commitment its header carries. HKDF-Expand's 76 bytes, key, base nonce and commitment, are
    /// two blocks of HMAC-SHA-512 with `dek` as the PRK.
    pub(crate) fn derive(
        dek: &[u8],
        salt: &Salt,
        aad: &[u8],
    ) -> Result<(Self, Commitment), Failure> {
        let first_block = Self::hmac_block(dek, &[HKDF_INFO_PREFIX, salt, aad, &[1]])?;
        let first = first_block.as_sensitive_bytes();
        let second_block = Self::hmac_block(dek, &[first, HKDF_INFO_PREFIX, salt, aad, &[2]])?;
        let second = second_block.as_sensitive_bytes();

        let derived_len = DERIVED_CHUNK_KEY_LEN + AeadAlgorithm::NONCE_LEN;
        let mut commitment: Commitment = [0; STREAM_KEY_COMMITMENT_LEN];
        let (from_first, from_second) = commitment.split_at_mut(first.len() - derived_len);
        from_first.copy_from_slice(&first[derived_len..]);
        from_second.copy_from_slice(&second[..from_second.len()]);
        let cipher = Self {
            derived: SecretValue::new(first[..derived_len].to_vec()),
            backend: PhantomData,
        };
        Ok((cipher, commitment))
    }

    /// One block of HKDF-Expand, in a buffer that is zeroised when it is dropped. The backend's
    /// own working copies of the tag are not.
    fn hmac_block(dek: &[u8], message: &[&[u8]]) -> Result<SecretValue, Failure> {
        let mut block = SecretValue::new(vec![0; size_of::<HmacSha512>()]);
        let out = <&mut HmacSha512>::try_from(block.ref_sensitive_value_mut().as_mut_slice())
            .map_err(|_| Failure::Operation)?;
        B::hmac_sha512(dek, message, out)?;
        Ok(block)
    }

    /// Encrypts chunk `index`, `in_out`, in place and returns its tag.
    pub(crate) fn encrypt_in_place(&self, index: u64, in_out: &mut [u8]) -> Result<Tag, Failure> {
        B::seal_in_place(CHUNK_ALGORITHM, self.key(), &self.nonce(index), &[], in_out)
    }

    /// Decrypts chunk `index`, `in_out`, its ciphertext and tag, in place, and returns the length
    /// of its plaintext at the start of `in_out`.
    pub(crate) fn decrypt_in_place(&self, index: u64, in_out: &mut [u8]) -> Result<usize, Failure> {
        B::open_in_place(CHUNK_ALGORITHM, self.key(), &self.nonce(index), &[], in_out)
    }

    fn key(&self) -> &[u8] {
        &self.derived.as_sensitive_bytes()[..DERIVED_CHUNK_KEY_LEN]
    }

    /// The base nonce XORed with `index` as a 96-bit big-endian integer.
    fn nonce(&self, index: u64) -> Nonce {
        let mut nonce: Nonce = [0; AeadAlgorithm::NONCE_LEN];
        nonce.copy_from_slice(&self.derived.as_sensitive_bytes()[DERIVED_CHUNK_KEY_LEN..]);
        let counter_bytes = index.to_be_bytes();
        let counter = &mut nonce[AeadAlgorithm::NONCE_LEN - counter_bytes.len()..];
        for (byte, index_byte) in counter.iter_mut().zip(counter_bytes) {
            *byte ^= index_byte;
        }
        nonce
    }

    #[cfg(test)]
    pub(crate) fn derived(&self) -> &[u8] {
        self.derived.as_sensitive_bytes()
    }
}
