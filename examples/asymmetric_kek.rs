//! A producer that holds only the public half of an RSA KEK encrypts a value through an envelope,
//! and a reader that holds the private half decrypts it. Both load their half from PEM, as a
//! deployment does: the producer from a `PUBLIC KEY` (SubjectPublicKeyInfo) block, pinned to the
//! fingerprint the administration published, and the reader from a PKCS#8 `PRIVATE KEY` block. The
//! local asymmetric KMS stands in for a cloud KMS, so the example needs no credentials.
//!
//! ```sh
//! cargo run --example asymmetric_kek --features aws-lc
//! ```

use std::num::NonZeroU32;

use kms_aead::backends::AwsLc;
use kms_aead::formats::{Envelope, PrivateKeyFormat, PublicKeyFormat};
use kms_aead::providers::{
    KmsKeyVersion, LocalAsymmetricKek, LocalAsymmetricKmsProvider, LocalKekId, LocalKekVersion,
    PublicKeyKekProvider,
};
use kms_aead::{
    AsymmetricKekAlgorithm, AsymmetricKekPublicKey, Encrypted, KekRef, KmsAeadEnvelope, KmsProvider,
};
use secret_vault_value::SecretValue;

const AAD: &[u8] = b"orders/1042";
const KEK_ID: &str = "orders-kek";

// A throwaway test key that stands in for the operator's key files. Never use it elsewhere.
const PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIG/QIBADANBgkqhkiG9w0BAQEFAASCBucwggbjAgEAAoIBgQDeda4P3hLiP8+H
D3X9tULckKahZihzl9PFeXbwsCCt+/n9vYVHxS+PeqUj+t+UHKmN2omiSjNmFfys
AyWj80AVFwNBMPbNp+po5voOcGYev+tRBDWs0Gs9nhsAi0S2BTIJGA2bFQQidHEi
tn5wWd9SvSXtUKDJbz9XcoN7e1oUcJUUNZ0g7l4b4C7zYqnEWKTXXUWPALSfErq3
HoxBLs+eRywSqd0ic5IBwRSrhfgA3b9f+lNZJ1x+SaH+izUzRGbn3qqobgfVYfa/
1npEq8Mi6JiOOO6lJHFxbEUawSzVsBtLymDUWwDshOA/GuvhV1m8hDYdcU5ZCCu+
oT5PhOomj1/sugiK9z9HBdUogeNklzpnDcN8TTmh7n6tVHK9m6S75vpqYUVjwVsH
wregrU3Dm+Kzvh4LEX6Bshh8M4fddAAiqk4uhM7Z3/N4IpaSu0aI53STmU73hY5+
4EDNtyS/JyHgpzxuyQQ7a+H/xw/1LPLDinkMbZHq47YOrrOqfacCAwEAAQKCAYBX
VikvlpagV8AAfNvsbrjgwjOBIwvXkfB002KUTPmPhOEZMso8KpipAlQKQ6h6TCRv
CjDF087JEfHAkH27F7l9bir7cZ87j2RyqdfbSlp1URCwHnB6N9sadlOQi5y+v1xt
AJH65C3a3w85ux75ufb400SsHl75pmDeUpl3Ja7wXmDQ7dmR/7NXy1RzfjU7Xjfd
S4OPCI5g82f1k5spzhh5weR2MVUdfPUCFk0op/B9WpGTO0J0uoTQGdVtCzcoOP5Y
Dzg5rMmv8QiJHgg8e4+OvhfqhBtd47uB245c9JMNSBtK+7WygmDTSeLo6tVxai1g
ld1aqmc7kPgpEC3F3kxhBx3o7OMSr8AtiROgldIyOk/XkuKw/XtOFP7j7Xexvh2d
8nW7OnqxLUyI5/XTbu051kMHLZJScegJuAz4lUM1CVIVKTzx8SdAqn1J5Zn6h9Aw
oD7vbr5TL7lxkb9bBdkX3SaXcfXoewic9OvQtsiwnPBFzi8NJToCQo4yDr+jPSUC
gcEA+cohtQh0TfrXynE430GBeK9bKmJDwsbEcmGKtgFwKKsTAKEYZYgs/pl73kaL
rNa4sSHO13SHoOQap3FnOA1Ig8x58vXYLaS6VQBJBlV0+9UR41P9N+ZQi7du+gfd
zw7VcMFDM6dh/cXyaAQjsFRHKQ4RA0emWJvj8WC4jfAfTwvdQYN35W6EoE2SDmO8
vMY9GroyXSORoda7vFF9tc4gng3+E5gnXRkEo2kOv8hDQM+9U1Go75mpvXgyWjir
VF2DAoHBAOP9mSAAQpshfQf8XhS12UUeWCI0kE8HvdNB/IJM1AYxJgMqWcm1QlMC
0Q4x9rnmxPwrP36LMmKNRG995aCutxvg8SYRvJWhF9v+3A68xfc/X8f325cvvdrW
Yrnlrlsq4GV6ddAO8Z1paP13JFWgvc3qDxB++DT0/AyiFF8hScJS6ZRcqKJ2xmDv
bOBP1CsJ8uepstOHUW5lu1IUaWjMi0N6Ey8h3R9onlnOLH9GMwxA0s9SQC1ryX9s
rI6gxPjqDQKBwQC+t1whEsFqQJm+EdBwdV1bPdgHdltyPb0D8AGukU6HXob1tgog
i2Z/RcTTo11Fq/P8GmoJCwn7B+5p5iX/H/U73EVIAfj6cIlsGPmoglr9ZGNyBFCT
+5+H7ZgoAxWR4CuLGaQrriMdVaONU4vEN7TVXc4TiQMzKGNTipuek7Xz7oUSXkSO
wmE028Umg3Q5VcqVu5B0mJG61W8li7rFswooY1qYr1VuuYlXEwGV4FupAnP1R6YK
unJlHX6kcBwwH+0CgcBAaeHdXLV0xt1gaDjceRRNpukXoOo0qedDzJze433z0eb/
dfOwPXnjoiQWcp9WnpCA/mcOBZ3Soj73kQZTg4lQYxk+vDwfukfXbAYYU9VKqakS
AkEUUfS941w5UV8VeuOzSAoJIm+5HZMAKa0mVCfMCZj//B98NssPdqtyxSDlui8s
L5GldRFPSdXk+ijjkAgE07kmclDbc/qckg/GACRIiDDrXBHxUcmLbei8fMTnbVki
IgbnzlA7pCSMl3ePK/ECgcB2r+p4ris/L5skfOAIM8v3M9TlYqhAVffJxiWNdX+R
f8q6hLqMw0Tk6D5JrGkgykVjbSg5ikADKdpl5IjjEKf5035b62Sij7sW/ztrCAsd
dU/jFfleWsE3Cab289bf1pTKqm71fAcct1PexRFek5I/O0Ggt/+WDhhQ0Df2xhrR
jQMONAiaFbqS9Po2tPLquOd+C9MQlYPHlkEuJpnQ66G64tXcaVk/vhbBYip0F3Yn
TZW7XdBWuU3/tnoMuY0Lg/g=
-----END PRIVATE KEY-----
";

const PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA3nWuD94S4j/Phw91/bVC
3JCmoWYoc5fTxXl28LAgrfv5/b2FR8Uvj3qlI/rflBypjdqJokozZhX8rAMlo/NA
FRcDQTD2zafqaOb6DnBmHr/rUQQ1rNBrPZ4bAItEtgUyCRgNmxUEInRxIrZ+cFnf
Ur0l7VCgyW8/V3KDe3taFHCVFDWdIO5eG+Au82KpxFik111FjwC0nxK6tx6MQS7P
nkcsEqndInOSAcEUq4X4AN2/X/pTWSdcfkmh/os1M0Rm596qqG4H1WH2v9Z6RKvD
IuiYjjjupSRxcWxFGsEs1bAbS8pg1FsA7ITgPxrr4VdZvIQ2HXFOWQgrvqE+T4Tq
Jo9f7LoIivc/RwXVKIHjZJc6Zw3DfE05oe5+rVRyvZuku+b6amFFY8FbB8K3oK1N
w5vis74eCxF+gbIYfDOH3XQAIqpOLoTO2d/zeCKWkrtGiOd0k5lO94WOfuBAzbck
vych4Kc8bskEO2vh/8cP9Szyw4p5DG2R6uO2Dq6zqn2nAgMBAAE=
-----END PUBLIC KEY-----
";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let version = LocalKekVersion::from(NonZeroU32::MIN);
    let algorithm = AsymmetricKekAlgorithm::RsaOaepSha256;

    // The reader holds the private half.
    let kms = LocalAsymmetricKmsProvider::<AwsLc>::new(
        LocalKekId::try_from(KEK_ID.to_string())?,
        algorithm,
        vec![LocalAsymmetricKek::from_secret(
            version,
            SecretValue::from(PRIVATE_KEY_PEM),
            PrivateKeyFormat::Pkcs8Pem,
        )?],
    )?;

    // The administration publishes the fingerprint of the key next to the PEM. `pinned` refuses a
    // key whose fingerprint differs: a key taken from an unauthenticated place encrypts for
    // whoever supplied it.
    let fingerprint = kms.public_key(None)?.fingerprint();
    let public_key = AsymmetricKekPublicKey::new(
        KekRef::new(KmsProvider::Local, KEK_ID),
        Some(KmsKeyVersion::from(version)),
        algorithm,
        PUBLIC_KEY_PEM.as_bytes().to_vec(),
        PublicKeyFormat::SpkiPem,
    )?;
    println!(
        "public key of {}, fingerprint {fingerprint}",
        public_key.kek()
    );

    let public_half = PublicKeyKekProvider::<AwsLc>::pinned(public_key, fingerprint)?;

    let producer = KmsAeadEnvelope::<_, AwsLc>::new(public_half)?;
    let secret_value = SecretValue::from("card-token-4242");
    let encrypted: Encrypted<SecretValue, Envelope> = producer.encrypt(AAD, &secret_value).await?;
    println!(
        "producer encrypted {} bytes without a KMS call",
        encrypted.value().len()
    );

    // `producer.decrypt(AAD, &encrypted)` does not compile: the producer's provider implements
    // encryption and not decryption.

    let reader = KmsAeadEnvelope::<LocalAsymmetricKmsProvider<AwsLc>, AwsLc>::new(kms)?;
    let decrypted: SecretValue = reader.decrypt(AAD, &encrypted).await?;
    assert_eq!(decrypted, secret_value);
    println!("reader decrypted the value with the private half");

    Ok(())
}
