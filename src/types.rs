use crate::errors::*;
use crate::KmsAeadResult;
use rvstruct::*;
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, Eq, PartialEq, ValueStruct)]
pub struct CipherText(pub Vec<u8>);

impl CipherText {
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.value())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, ValueStruct)]
pub struct DataEncryptionKey(pub SecretValue);

#[derive(Debug, Clone, Eq, PartialEq, ValueStruct)]
pub struct EncryptedDataEncryptionKey(pub Vec<u8>);

impl EncryptedDataEncryptionKey {
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.value())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, ValueStruct)]
pub struct CipherTextWithEncryptedKey(pub Vec<u8>);

impl CipherTextWithEncryptedKey {
    pub fn new(cipher_text: &CipherText, encrypted_dek: &EncryptedDataEncryptionKey) -> Self {
        let mut value = Vec::with_capacity(
            std::mem::size_of::<usize>() + encrypted_dek.value().len() + cipher_text.value().len(),
        );
        value.extend_from_slice(&encrypted_dek.value().len().to_be_bytes());
        value.extend_from_slice(encrypted_dek.value());
        value.extend_from_slice(cipher_text.value());

        value.into()
    }

    pub fn separate(&self) -> KmsAeadResult<(CipherText, EncryptedDataEncryptionKey)> {
        let us_len = std::mem::size_of::<usize>();

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
