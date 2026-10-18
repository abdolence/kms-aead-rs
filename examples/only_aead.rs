use kms_aead::*;
use secret_vault_value::SecretValue;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let encryption = AeadCipher::<Ring>::new(AeadAlgorithm::ChaCha20Poly1305)?;
    let dek = encryption.generate_dek()?;

    let secret_value = SecretValue::from("test-secret");
    let test_aad = b"test-aad";

    let cipher_text: Encrypted<SecretValue, formats::Bare> =
        encryption.encrypt_bare(test_aad, &secret_value, &dek)?;

    println!("Encrypted to {:?}", cipher_text.to_hex_string());

    let secret_value: SecretValue = encryption.decrypt_bare(test_aad, &cipher_text, &dek)?;

    println!(
        "We have our secret back: {}",
        secret_value == SecretValue::from("test-secret")
    );

    Ok(())
}
