use crate::errors::*;
use crate::KmsAeadResult;
use rvstruct::*;
use secret_vault_value::SecretValue;
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, ValueStruct)]
pub struct CipherText(pub Vec<u8>);

impl CipherText {
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.value())
    }
}

impl ConstantTimeEq for CipherText {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value().ct_eq(other.value())
    }
}

impl PartialEq for CipherText {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[derive(Debug, Clone, ValueStruct)]
pub struct DataEncryptionKey(pub SecretValue);

impl ConstantTimeEq for DataEncryptionKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value()
            .as_sensitive_bytes()
            .ct_eq(other.value().as_sensitive_bytes())
    }
}

impl PartialEq for DataEncryptionKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[derive(Debug, Clone, ValueStruct)]
pub struct EncryptedDataEncryptionKey(pub Vec<u8>);

impl EncryptedDataEncryptionKey {
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.value())
    }
}

impl ConstantTimeEq for EncryptedDataEncryptionKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value().ct_eq(other.value())
    }
}

impl PartialEq for EncryptedDataEncryptionKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[derive(Debug, Clone)]
pub struct CipherTextWithEncryptedKey(pub Vec<u8>);

impl CipherTextWithEncryptedKey {
    pub fn new(cipher_text: &CipherText, encrypted_dek: &EncryptedDataEncryptionKey) -> Self {
        let mut value = Vec::with_capacity(
            std::mem::size_of::<u64>() + encrypted_dek.value().len() + cipher_text.value().len(),
        );
        value.extend_from_slice(&(encrypted_dek.value().len() as u64).to_be_bytes());
        value.extend_from_slice(encrypted_dek.value());
        value.extend_from_slice(cipher_text.value());

        value.into()
    }

    pub fn separate(&self) -> KmsAeadResult<(CipherText, EncryptedDataEncryptionKey)> {
        let us_len = std::mem::size_of::<u64>();

        if self.value().len() < us_len {
            return Err(KmsAeadEncryptionError::create(
                "INVALID_CIPHER_TEXT_FORMAT",
                "Unexpected len of cipher text to decode",
            ));
        }

        let len_slice = &self.0.as_slice()[0..us_len];
        let dek_len = usize::from_be_bytes(len_slice.try_into().unwrap());

        if self.value().len() < us_len + dek_len {
            return Err(KmsAeadEncryptionError::create(
                "INVALID_CIPHER_TEXT_FORMAT",
                "Unexpected len of cipher text to decode: DEK len is more than buffer",
            ));
        }

        let dek: EncryptedDataEncryptionKey =
            self.0.as_slice()[us_len..us_len + dek_len].to_vec().into();

        let cipher_text: CipherText = self.0.as_slice()[us_len + dek_len..].to_vec().into();
        Ok((cipher_text, dek))
    }

    pub fn to_hex_string(&self) -> String {
        hex::encode(self.value())
    }

    #[inline]
    pub fn value(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for CipherTextWithEncryptedKey {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl ConstantTimeEq for CipherTextWithEncryptedKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value().ct_eq(other.value())
    }
}

impl PartialEq for CipherTextWithEncryptedKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    pub fn generate_cipher_text() -> BoxedStrategy<CipherText> {
        ("[a-zA-Z0-9]+")
            .prop_map(|(mock_str)| CipherText::from(mock_str.as_bytes().to_vec()))
            .boxed()
    }

    pub fn generate_encrypted_dek() -> BoxedStrategy<EncryptedDataEncryptionKey> {
        ("[a-zA-Z0-9]+")
            .prop_map(|(mock_str)| EncryptedDataEncryptionKey::from(mock_str.as_bytes().to_vec()))
            .boxed()
    }

    proptest! {
        #[test]
        fn cipher_text_with_key_encoding_test(mock_cipher_text in generate_cipher_text(), mock_encrypted_dek in generate_encrypted_dek()) {
            let cipher_text_with_key = CipherTextWithEncryptedKey::new(&mock_cipher_text, &mock_encrypted_dek);
            let (decoded_cipher_text,decoded_dek) = cipher_text_with_key.separate().unwrap();
            assert_eq!(decoded_cipher_text, mock_cipher_text);
            assert_eq!(decoded_dek, mock_encrypted_dek);
        }
    }
}
