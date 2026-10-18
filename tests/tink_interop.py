"""Tink on a Cloud KMS key and an AWS KMS key, for checking kms-aead against it.

Checked with Tink 1.16.1 for Python (`pip install 'tink[gcpkms,awskms]==1.16.1'`):

    python -I tests/tink_interop.py encrypt > tink.jsonl
    cargo run --example tink_interop --features gcp-kms-encryption,aws-kms-encryption,aws-lc \\
        -- decrypt < tink.jsonl
    cargo run --example tink_interop --features gcp-kms-encryption,aws-kms-encryption,aws-lc \\
        -- encrypt > kms-aead.jsonl
    python -I tests/tink_interop.py decrypt < kms-aead.jsonl
    cargo run --example tink_interop --features gcp-kms-encryption,aws-kms-encryption,aws-lc \\
        -- export > kms-aead-keysets.jsonl
    python -I tests/tink_interop.py read-keysets < kms-aead-keysets.jsonl > tink-keysets.jsonl
    cargo run --example tink_interop --features gcp-kms-encryption,aws-kms-encryption,aws-lc \\
        -- decrypt < tink-keysets.jsonl
    cargo run -p kms-aead-keyring --example tink_export --features ci-tink,aws-lc \\
        | python -I tests/tink_interop.py read-keysets

`encrypt` and `decrypt` use Tink's KmsEnvelopeAead. `read-keysets` reads each keyset kms-aead
exported with KeysetHandle.read and the KMS client of the key URI kms-aead gave, opens the value
kms-aead sealed with it, and writes a value of its own sealed with the keyset for a keyset line
with "wrapped_key"; it reports on stderr.

The keys come from the variables of the live tests: PROJECT_ID, PROJECT_LOCATION, KMS_KEY_RING
and KMS_KEY for Cloud KMS, and KMS_KEY_ID, the key ARN, for AWS KMS, with ACCOUNT_ID for the
example. A KMS whose variables are not set is skipped. Cloud KMS uses the application default
credentials, AWS KMS the credentials boto3 finds.

Each line is one value: {"kms": "gcp" or "aws", "algorithm": the kms-aead name, "aad",
"plain_text" and "value" in hex}, and for a keyset "key_uri", "keyset" and "wrapped_key", the key
wrapped by the KMS key, which kms-aead opens Tink's value with. Tink for Python has no
ChaCha20Poly1305Key, so `decrypt` and `read-keysets` skip the chacha20-poly1305 values that
kms-aead writes.
"""

from importlib import metadata
import json
import os
import sys

import tink
from tink import aead
from tink.integration import awskms
from tink.integration import gcpkms

TEMPLATES = {
    'aes-128-gcm': aead.aead_key_templates.AES128_GCM,
    'aes-256-gcm': aead.aead_key_templates.AES256_GCM,
    'aes-256-gcm-siv': aead.aead_key_templates.AES256_GCM_SIV,
}


def remote_aead(key_uri):
  if key_uri.startswith('gcp-kms://'):
    return gcpkms.GcpKmsClient(key_uri).get_aead(key_uri)
  return awskms.AwsKmsClient(key_uri, None).get_aead(key_uri)


def remote_aeads():
  remotes = {}
  if 'PROJECT_ID' in os.environ:
    remotes['gcp'] = remote_aead(
        'gcp-kms://projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}'.format(
            os.environ['PROJECT_ID'],
            os.environ['PROJECT_LOCATION'],
            os.environ['KMS_KEY_RING'],
            os.environ['KMS_KEY'],
        )
    )
  if 'KMS_KEY_ID' in os.environ:
    remotes['aws'] = remote_aead('aws-kms://' + os.environ['KMS_KEY_ID'])
  return remotes


def encrypt():
  for kms, remote in remote_aeads().items():
    for algorithm, template in TEMPLATES.items():
      aad = f'orders/{kms}/{algorithm}'.encode()
      plain_text = f"sealed by Tink {metadata.version('tink')}".encode()
      value = aead.KmsEnvelopeAead(template, remote).encrypt(plain_text, aad)
      print(json.dumps({
          'kms': kms,
          'algorithm': algorithm,
          'aad': aad.hex(),
          'plain_text': plain_text.hex(),
          'value': value.hex(),
      }))


def decrypt():
  remotes = remote_aeads()
  failures = 0
  for line in sys.stdin:
    case = json.loads(line)
    name = f"{case['kms']} {case['algorithm']}"
    template = TEMPLATES.get(case['algorithm'])
    if template is None:
      print(f'{name}: skipped, Tink for Python has no such key type')
      continue
    if case['kms'] not in remotes:
      print(f'{name}: skipped, its key is not configured')
      continue
    envelope = aead.KmsEnvelopeAead(template, remotes[case['kms']])
    plain_text = envelope.decrypt(
        bytes.fromhex(case['value']), bytes.fromhex(case['aad'])
    )
    if plain_text == bytes.fromhex(case['plain_text']):
      print(f'{name}: ok')
    else:
      print(f'{name}: another plain text')
      failures += 1
  sys.exit(1 if failures else 0)


def read_keysets():
  failures = 0
  for line in sys.stdin:
    case = json.loads(line)
    name = f"{case['kms']} {case['algorithm']} keyset"
    if case['algorithm'] not in TEMPLATES:
      print(f'{name}: skipped, Tink for Python has no such key type', file=sys.stderr)
      continue
    keyset = tink.read_keyset_handle(
        tink.BinaryKeysetReader(bytes.fromhex(case['keyset'])),
        remote_aead(case['key_uri']),
    )
    primitive = keyset.primitive(aead.Aead)
    aad = bytes.fromhex(case['aad'])
    if primitive.decrypt(bytes.fromhex(case['value']), aad) == bytes.fromhex(
        case['plain_text']
    ):
      print(f'{name}: ok', file=sys.stderr)
    else:
      print(f'{name}: another plain text', file=sys.stderr)
      failures += 1
    if 'wrapped_key' not in case:
      continue
    plain_text = f"sealed by Tink {metadata.version('tink')}".encode()
    print(json.dumps({
        'kms': case['kms'],
        'algorithm': case['algorithm'],
        'wrapped_key': case['wrapped_key'],
        'aad': case['aad'],
        'plain_text': plain_text.hex(),
        'value': primitive.encrypt(plain_text, aad).hex(),
    }))
  sys.exit(1 if failures else 0)


if __name__ == '__main__':
  aead.register()
  {'encrypt': encrypt, 'decrypt': decrypt, 'read-keysets': read_keysets}[
      sys.argv[1]
  ]()
