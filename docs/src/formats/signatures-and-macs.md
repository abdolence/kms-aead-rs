# Signature and MAC formats

The layouts of signatures and MACs, what they are computed over, the key ids of signing keys and
the test vectors. The layouts of every kind of value are listed on [Formats](../formats.md).

Detached and attached signatures and MACs are Tink-prefixed values:

| Layout | Type | Bytes |
|---|---|---|
| Detached signature | `Signature<T>` | `[0x01][key id: u32 BE][signature]` |
| Attached signature | `Signed<T>` | `[0x01][key id: u32 BE][w: u16 BE][signature: w][payload]` |
| Detached MAC | `Mac<T>` | `[0x01][key id: u32 BE][tag]` |
| Attached MAC | `WithMac<T>` | `[0x01][key id: u32 BE][w: u16 BE][tag: w][payload]` |

- `0x01` is the version of the layout. A later layout takes another first byte;
- the key id names the key that signed or computed the tag. It is not authenticated and is a hint
  only: a value whose id is changed verifies under no key;
- the signature is the raw signature of the key's algorithm: 64 bytes for Ed25519 (RFC 8032) and
  `r || s` with each scalar left-padded to 32 bytes for P-256. The algorithm is not in the value:
  the verifying key fixes it;
- the tag is the full HMAC output, never truncated: 32 bytes under HMAC-SHA256, 64 under
  HMAC-SHA512. The key version's algorithm fixes the length;
- `w` is the signature or tag length of an attached value, 1 to 65,535, so a reader finds the payload at offset `7 + w`
  without knowing the key.

`TryFrom<Vec<u8>>` checks a value against its layout and fails with `INVALID_SIGNATURE_FORMAT` or
`INVALID_MAC_FORMAT`.

Every signature and every MAC is computed over the pre-image, never over the payload itself. It is
the Pre-Authentication Encoding (PAE) of
[DSSE](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md), the Dead Simple Signing
Envelope, with the SHA-256 of the payload as its body:

```text
pre-image = "DSSEv1" SP DEC(len(type)) SP type SP "32" SP SHA-256(payload)
```

- `SP` is one byte `0x20`;
- `DEC(n)` is `n` in ASCII decimal with no leading zeros;
- `type` is the payload type: 1 to 255 bytes of visible ASCII, `0x21` to `0x7E`, such as
  `application/vnd.example.invoice+json`;
- `SHA-256(payload)` is the 32-byte digest of the payload bytes.

The pre-image is 46 to 302 bytes long. Ed25519 signs it as it is, and ECDSA P-256 signs its SHA-256.
A MAC is the HMAC of the pre-image. The payload is the bytes `Signable::to_payload` returns, which
the library neither parses nor re-serialises.

The key id of a signing key is derived from its public key:

```text
thumbprint input = {"crv":"Ed25519","kty":"OKP","x":"<base64url of the 32 bytes>"}
                 | {"crv":"P-256","kty":"EC","x":"<base64url of x>","y":"<base64url of y>"}
digest           = SHA-256(thumbprint input)
kid              = base64url(digest), without padding, 43 characters
key id           = the first four bytes of digest, as a big-endian u32
```

The thumbprint input is the JWK thumbprint of [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638): the
required members of the key in lexicographic order, with no whitespace. A publisher with a numbering
of its own sets the id instead, and the published key carries it as the integer member
`kms_aead_key_id`. The key id of a MAC key is the keyring's id of the version, see
[Keyring key ids](./keyring-records.md#keyring-key-ids).

A set of public keys is a JWK Set ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)). Each key has
`kty`, `crv`, `x` (and `y`), `kid` the full thumbprint, `use` `sig` and `alg` `EdDSA` or `ES256`,
and `kms_aead_key_id` where the publisher set the id:

```json
{"keys":[
  {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
   "kid":"kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k","use":"sig","alg":"EdDSA"},
  {"kty":"EC","crv":"P-256","x":"YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y",
   "y":"eQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk",
   "kid":"DOvxvJiAdIqVWIkFt5hDtCunXLF0BV4-JGv4f-ALSm0","use":"sig","alg":"ES256"}
]}
```

## The signed keyring record

A keyring record carries its signature as the top-level member `signature`, the standard base64 of
a detached `Signature` over the record's canonical document:

```text
canonical = JCS(record document without its "signature" member)
pre-image = PAE("application/vnd.kms-aead.keyring-record+json", SHA-256(canonical))
```

JCS is the JSON Canonicalization Scheme of [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785):
members sorted by name, no whitespace, standard string escaping with non-ASCII kept as UTF-8 and
control characters as `\u00XX`. It is computed over the parsed JSON document with every member
kept, including members this release does not know, so a later release may add members and sign
records that carry them. A record holds strings, integers, booleans, `null`, arrays and objects; a
fraction, an exponent or an integer beyond 2^53 anywhere in it is `RECORD_INVALID`. The canonical
document of a record with a `null`, a nested `compromised`, a note holding `é` and the control
character `0x07`, and a member `future` this release does not define, on one line of 579 bytes
without the line breaks shown here:

```text
{"algorithms":{"beacon":null,"deterministic":null,"mac":null,"randomized":"aes-256-gcm"},
"created_at":"2026-10-25T09:00:00Z","future":{"a":[true,null],"b":1},"id":"tenant-42",
"kek":{"key":"tenant-kek","provider":"local"},"schema":1,"seal_epoch":1,
"updated_at":"2026-10-25T09:00:00Z","versions":[{"algorithm":"aes-256-gcm",
"compromised":{"at":"2026-10-25T09:00:00Z","note":"clé \u0007"},
"created_at":"2026-10-25T09:00:00Z","encrypted_dek":"AQ==","kek_version":"1","key_id":1,
"seal_epochs":{"end":null,"start":1},"state":"decrypt_only",
"state_changed_at":"2026-10-25T09:00:00Z"}]}
```

Its SHA-256 is `195ad529d5ec1beec7f6d806169d598723bf067c6abd6b522ab330310f2d79d2`, with `é` as the two
bytes `c3 a9`. The pre-image is `DSSEv1 44 application/vnd.kms-aead.keyring-record+json 32 ` and that
digest, 90 bytes. Under the Ed25519 key of the vectors below the stored member is
`"signature": "AZD6yv6RAlxJsp1uzsdIQxlvyawlD282Dfrtg3QthYeSPnQ02B6jbpOBFA65Y2Zq5lILiXyyTCxj9bv36JGSWC2H2UAG"`.

## Signature and MAC test vectors

Generated with Python's `cryptography` 50.0.2 from published keys, so that nothing in them is
secret. Payload type `application/vnd.example.invoice+json`, payload
`{"number":"INV-1042","customer":"Northwind Traders","currency":"EUR","total_cents":12500}`:

```text
SHA-256(payload)       7b43154b748a12c6909cba38acd83fff12a11b6345effb807b21c7ce465e4cd1
pre-image (82 bytes)   445353457631203336206170706c69636174696f6e2f766e642e6578616d706c652e
                       696e766f6963652b6a736f6e203332207b43154b748a12c6909cba38acd83fff12a1
                       1b6345effb807b21c7ce465e4cd1
SHA-256(pre-image)     4617fb02679fc4831b071fb2a064a33c2999e5f6a3c2fb65a96474d5663950be
```

Ed25519, the RFC 8032 section 7.1 test 1 key, seed
`9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`:

```text
public key             d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
SubjectPublicKeyInfo   302a300506032b6570032100 || public key
PKCS#8                 302e020100300506032b657004220420 || seed
thumbprint input       {"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
kid                    kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
key id                 90facafe = 2432355070
signature              21c5f4d55977b19640f25f0e248d4c9765aa0d210f9c781b61b46dece74d4dec
                       b950acf3947659a9fff322b88ad8562e2c9ee4392440a4da901b7fec385f1102
detached (69 bytes)    0190facafe || signature
attached (160 bytes)   0190facafe0040 || signature || payload
```

ECDSA P-256, the RFC 6979 A.2.5 key, private scalar
`c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721`. ECDSA signing is randomised,
so the signature verifies and is not reproduced:

```text
x                      60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6
y                      7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299
SubjectPublicKeyInfo   3059301306072a8648ce3d020106082a8648ce3d030107034200 || 04 || x || y
thumbprint input       {"crv":"P-256","kty":"EC","x":"YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y","y":"eQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk"}
kid                    DOvxvJiAdIqVWIkFt5hDtCunXLF0BV4-JGv4f-ALSm0
key id                 0cebf1bc = 216789436
signature as DER       30450220409b9927a7f27d61f6d7360b9b91941fa6dd14db553a55d0dd573fc9db7fccb7
                       022100af3a4aaab89c0684256afe5db6aa53e4569286bc2c2f6435fe7563db215b5976
r || s                 409b9927a7f27d61f6d7360b9b91941fa6dd14db553a55d0dd573fc9db7fccb7
                       af3a4aaab89c0684256afe5db6aa53e4569286bc2c2f6435fe7563db215b5976
detached (69 bytes)    010cebf1bc || r || s
```

HMAC-SHA256 under the key of 32 bytes `0x42`, key id `3221225473`, the first MAC version of a
keyring:

```text
tag                    a2ca416600c31c19620b0b021986b1116ef1186318b32d819659093c125737f9
detached (37 bytes)    01c0000001 || tag
attached (128 bytes)   01c00000010020 || tag || payload
```

HMAC-SHA512 under the key of 64 bytes `0x42`, key id `3221225474`, the second MAC version:

```text
tag                    620e50560d4f30c943664d8671c2788db8a1165c742ab379afaf9047dfa3610a
                       ca85a98e462c791f19d966e04b90748ce397755de7dc86a49f511a9021331ac3
detached (69 bytes)    01c0000002 || tag
attached (160 bytes)   01c00000020040 || tag || payload
```

The primitives are checked against [Wycheproof](https://github.com/C2SP/wycheproof/tree/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1)
on every backend, and these vectors on ring, aws-lc-rs, RustCrypto and, with
`tests/webcrypto_vectors.mjs`, WebCrypto under Node.
