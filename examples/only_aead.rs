use kms_aead::backends::Ring;
use kms_aead::formats::Bare;
use kms_aead::{AeadAlgorithm, AeadCipher, Encrypted};
use secret_vault_value::SecretValue;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::ChaCha20Poly1305)?;
    let dek = cipher.generate_dek()?;

    let secret_value = SecretValue::from("test-secret");
    let test_aad = b"test-aad";

    let cipher_text: Encrypted<SecretValue, Bare> =
        cipher.encrypt_bare(test_aad, &secret_value, &dek)?;

    println!("Encrypted to {}", cipher_text.to_hex_string());

    let decrypted: SecretValue = cipher.decrypt_bare(test_aad, &cipher_text, &dek)?;
    assert_eq!(decrypted, secret_value);

    println!("Decrypted to the original value");

    Ok(())
}
