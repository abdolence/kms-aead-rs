# Streamed values

This page has the layouts written by the stream encryptors of kms-aead and kms-aead-keyring, and the
arithmetic of a range read. Read it to parse a streamed value without the library, or to fetch a
byte range of one from a store. The layouts of every kind of value are listed on
[Formats](../formats.md).

A streamed value is a header and chunks. Every length is in bytes and integers are big-endian. The
prefixed form, the one of `AeadCipher::stream_encryptor` and of the keyring:

```text
offset          len     field
     0            1     0x01, Tink's output prefix of type TINK
     1            4     key id, u32: the keyring version that encrypted the value, or the caller's KeyId
     5           24     salt, random per value
    29           32     key commitment
    61       16,400     chunk 0: 16,384 bytes of ciphertext and a 16-byte tag
    61 + k × 16,400     chunk k
```

The bare form is a Cobblestone-256 message, the chunked AES-256-GCM format with a key commitment
that [C2SP chunked encryption](https://c2sp.org/chunked-encryption) specifies, with the caller's AAD as its *context* and the DEK as its *input key*:

```text
offset          len     field
     0           24     salt
    24           32     key commitment
    56       16,400     chunk 0
    56 + k × 16,400     chunk k
```

The envelope form, the one `KmsAeadEnvelope::stream_encryptor` writes, puts the encrypted DEK in
front of the bare form, as [Tink's KMS envelope](./values.md#tinks-kms-envelope) puts it in front of a bare
value:

```text
offset          len     field
     0            4     w, u32: the length of the encrypted DEK, 1 to 4,096
     4            w     encrypted DEK, the provider's EncryptedDataEncryptionKey
 4 + w           24     salt
28 + w           32     key commitment
60 + w       16,400     chunk 0
60 + w + k × 16,400     chunk k
```

- the header `H` is 61 bytes in the prefixed form, 56 in the bare form and `60 + w` in the
  envelope form. From the Cobblestone header on, the forms are the same;
- every chunk but the last is 16,400 bytes as stored. The last chunk is 16 to 16,399 bytes, the tag
  and 0 to 16,383 bytes of ciphertext, so a plaintext of a multiple of 16,384 bytes ends with a
  tag alone. An empty plaintext is the header and one tag, 77 bytes prefixed, 72 bare and `76 + w`
  in the envelope form. There is one chunking for each length;
- only the first byte of a prefixed header is checked when it is read. The key id is not
  authenticated: it names the key that decrypts the value;
- a reader of the envelope form reads `w` from the first 4 bytes, refuses a `w` outside 1 to 4,096
  before it fetches or allocates anything, then reads the `60 + w` bytes of the header. The
  encrypted DEK is not authenticated either: another value's encrypted DEK decrypts to another DEK,
  which fails the key commitment;
- no byte tells the bare form from the others, since a bare value starts with its random salt. The
  call names the form.

The keys come from the DEK `K` of 32 bytes, the salt and the AAD `A`:

HKDF-Expand is the key derivation step of HKDF that turns a pseudorandom key (PRK) into output
keys, and the DEK is the PRK here:

```text
key || base nonce || commitment = HKDF-Expand(SHA-512, PRK = K,
    info = "c2sp.org/chunked-encryption@v1+" || "AEAD_AES_256_GCM" || 0x00 || salt || A,
    length = 32 + 12 + 32)
```

With a 32-byte PRK, HKDF-Expand is two HMAC-SHA-512 calls: `T1 = HMAC(K, info || 0x01)` gives the key
(`T1[0..32]`), the base nonce (`T1[32..44]`) and `commitment[0..20]` (`T1[44..64]`), and
`T2 = HMAC(K, T1 || info || 0x02)` gives `commitment[20..32]` (`T2[0..12]`). A reader derives all
three and compares the commitment in constant time before it decrypts a chunk. The AAD is bound here
and nowhere else: each chunk's GCM associated data is empty.

Chunk `k` holds plaintext bytes `[k × 16,384, (k + 1) × 16,384)` and is
`AES-256-GCM(key, N_k, aad = "", M_k)`, with the nonce `N_k = base nonce XOR k`, `k` as a 96-bit
big-endian integer. There is no final flag: the final chunk is the one that is shorter than a full
one.

For a plaintext of `L` bytes the stored length is `Z = H + L + 16 × n` with `n = L div 16,384 + 1`
chunks. From a stored length `Z`, with `body = Z - H`:

```text
Z < H + 16          refused: shorter than the header and one tag
n = body div 16,400 + 1
r = body - (n - 1) × 16,400     the final chunk as stored
r < 16              refused: r = 0 is a value cut at a chunk boundary, 1 to 15 no encryptor writes
n > 2^38            refused
L = body - 16 × n
```

A value holds at most 2^38 chunks, 4 PiB less one byte of plaintext. The refusals are
`STREAM_LENGTH`. `Z` is what the store reports: until the final chunk has been decrypted, `L` is the
store's word. A reader that reads the value to its end needs no `Z`: the bytes after the last full
chunk are the final chunk, and the rules above hold for the length it read.

For a plaintext range `[a, b)` with `a <= b <= L`, the chunks to decrypt and the bytes to fetch are
below. A range open at the start has `a = 0` and one open at the end has `b = L`, so `..` is `[0, L)`:

```text
first = a div 16,384
end   = n                      if b == L: the final chunk, even when it holds no plaintext
        first                  if a == b < L
        (b - 1) div 16,384 + 1 otherwise
ciphertext = [H + first × 16,400, min(Z, H + end × 16,400))
```

The reader cuts the decrypted plaintext to `[a - first × 16,384, b - first × 16,384)`. For
`a = 1,000,000` and `b = 1,064,512` the chunks are `61..65` and the bytes `[1,000,461, 1,066,061)`
prefixed or `[1,000,456, 1,066,056)` bare, and `4 + w` bytes further in the envelope form.

The two shortest vectors of the C2SP test file as prefixed values under key id 7, with the key
`59454c4c4f57205355424d4152494e452059454c4c4f57205355424d4152494e` and an empty AAD:

```text
vector 1, an empty plaintext, 77 bytes:
0100000007 43a2e39431cbae0389d3fc86adf46f7c3a24de88d9311617
e53f3164cc1d5dc738a66b97f0bf786565c31799c2f463d50a7e10046011dc6f
c3c939e3a5db7affb6191551669554fb

vector 2, a plaintext of 7 bytes, 84 bytes:
0100000007 a1a1b56f6db58cd1ede0c5c9db62aef20d3f96a6c594bb92
52bb38122de91236502b42a1d7fcab820ffa292940d2f86add212cfa42c38df1
9d3cc9139ee61a5990d3db57433514229beea49a8a72bd
```

The lines are the prefix and the salt, the commitment, and the final chunk. In the bare form the
vectors' `ct` are the stored values as they are.

Vector 2 in the envelope form, with the 7 bytes `wrapped` as the encrypted DEK, 90 bytes:

```text
0000000777726170706564 a1a1b56f6db58cd1ede0c5c9db62aef20d3f96a6c594bb92
52bb38122de91236502b42a1d7fcab820ffa292940d2f86add212cfa42c38df1
9d3cc9139ee61a5990d3db57433514229beea49a8a72bd
```

The first line is `w`, the encrypted DEK and the salt. A real encrypted DEK is the provider's, see
[Encrypted DEKs](./values.md#encrypted-deks). Its bytes play no part in the key derivation, which takes the
DEK.
