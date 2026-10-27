"""Cobblestone-256 of pyca/cryptography, for checking kms-aead's streamed values against it.

Checked with cryptography 50.0.2 (`pip install cryptography==50.0.2`), the first series that has
`cryptography.cobblestone`:

    cargo run --example cobblestone_interop --features stream,ring -- encrypt > kms-aead.jsonl
    python -I tests/cobblestone_interop.py decrypt < kms-aead.jsonl
    python -I tests/cobblestone_interop.py encrypt > pyca.jsonl
    cargo run --example cobblestone_interop --features stream,ring -- decrypt < pyca.jsonl

`decrypt` reads each value kms-aead wrote in the bare, prefixed and envelope forms, strips the key
reference in front of the Cobblestone message (nothing, 5 bytes, or 4 + w bytes by the length w in
the first 4), and decrypts the rest with the DEK as the key and the AAD as the context. `encrypt`
writes a bare value of its own for each plaintext length, for kms-aead to decrypt.
"""

import json
import sys

from cryptography.cobblestone import (
    Cobblestone256Decryptor,
    Cobblestone256Encryptor,
)

# Both sides use the same lengths: either side of the 16,384-byte chunk, and whole chunks.
LENGTHS = [0, 1, 16383, 16384, 16385, 32768, 40000]

# The delivery size of the plaintext and the value, which no chunk boundary divides.
FRAME_LEN = 1400


def frames(data):
  return (data[start : start + FRAME_LEN] for start in range(0, len(data), FRAME_LEN))


def key_reference_len(form, value):
  if form == 'bare':
    return 0
  if form == 'prefixed':
    assert value[0] == 0x01, 'a prefixed value starts with the Tink output prefix 0x01'
    return 5
  assert form == 'envelope', f'unknown form {form}'
  return 4 + int.from_bytes(value[:4], 'big')


def decrypt():
  failures = 0
  for line in sys.stdin:
    case = json.loads(line)
    value = bytes.fromhex(case['value'])
    name = f"{case['form']} {len(bytes.fromhex(case['plain_text']))} bytes"
    decryptor = Cobblestone256Decryptor(
        bytes.fromhex(case['dek']), bytes.fromhex(case['aad'])
    )
    try:
      plain_text = b''.join(
          decryptor.update(frame)
          for frame in frames(value[key_reference_len(case['form'], value) :])
      ) + decryptor.finalize()
    except Exception as error:
      print(f'{name}: not decrypted, {type(error).__name__}')
      failures += 1
      continue
    if plain_text == bytes.fromhex(case['plain_text']):
      print(f'{name}: ok')
    else:
      print(f'{name}: another plain text')
      failures += 1
  sys.exit(1 if failures else 0)


def encrypt():
  for length in LENGTHS:
    dek = Cobblestone256Encryptor.generate_key()
    aad = f'interop/pyca/{length}'.encode()
    plain_text = bytes((offset * 7) % 253 for offset in range(length))
    encryptor = Cobblestone256Encryptor(dek, aad)
    value = b''.join(encryptor.update(frame) for frame in frames(plain_text))
    value += encryptor.finalize()
    print(json.dumps({
        'form': 'bare',
        'aad': aad.hex(),
        'dek': dek.hex(),
        'plain_text': plain_text.hex(),
        'value': value.hex(),
    }))


if __name__ == '__main__':
  {'encrypt': encrypt, 'decrypt': decrypt}[sys.argv[1]]()
