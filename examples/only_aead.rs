use kms_aead::*;
use secret_vault_value::SecretValue;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let encryption = AeadCipher::new(AeadBackend::Ring, AeadAlgorithm::ChaCha20Poly1305)?;
    let key = encryption.generate_key()?;

    let secret_value = SecretValue::from("test-secret");
    let test_aad = b"test-aad";

    let cipher_text = encryption.encrypt_value(test_aad, &secret_value, &key)?;

    println!("Encrypted to {:?}", cipher_text.to_hex_string());

    let secret_value = encryption.decrypt_value(test_aad, &cipher_text, &key)?;

    println!(
        "We have our secret back: {}",
        secret_value == SecretValue::from("test-secret")
    );

    Ok(())
}
