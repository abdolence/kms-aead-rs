"""Tink's KmsEnvelopeAead on a Cloud KMS key and an AWS KMS key, for checking kms-aead against it.

Checked with Tink 1.16.1 for Python (`pip install 'tink[gcpkms,awskms]==1.16.1'`):

    python -I tests/tink_interop.py encrypt > tink.jsonl
    cargo run --example tink_interop --features gcp-kms-encryption,aws-kms-encryption,aws-lc \\
        -- decrypt < tink.jsonl
    cargo run --example tink_interop --features gcp-kms-encryption,aws-kms-encryption,aws-lc \\
        -- encrypt > kms-aead.jsonl
    python -I tests/tink_interop.py decrypt < kms-aead.jsonl

The keys come from the variables of the live tests: PROJECT_ID, PROJECT_LOCATION, KMS_KEY_RING
and KMS_KEY for Cloud KMS, and KMS_KEY_ID, the key ARN, for AWS KMS. Cloud KMS uses the
application default credentials, AWS KMS the credentials boto3 finds.

Each line is one value: {"kms": "gcp" or "aws", "algorithm": the kms-aead name, "aad",
"plain_text" and "value" in hex}. Tink for Python has no ChaCha20Poly1305Key, so `decrypt` skips
the chacha20-poly1305 values that kms-aead writes.
"""

from importlib import metadata
import json
import os
import sys

from tink import aead
from tink.integration import awskms
from tink.integration import gcpkms

TEMPLATES = {
    'aes-128-gcm': aead.aead_key_templates.AES128_GCM,
    'aes-256-gcm': aead.aead_key_templates.AES256_GCM,
    'aes-256-gcm-siv': aead.aead_key_templates.AES256_GCM_SIV,
}


def remote_aeads():
  gcp_key = 'gcp-kms://projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}'.format(
      os.environ['PROJECT_ID'],
      os.environ['PROJECT_LOCATION'],
      os.environ['KMS_KEY_RING'],
      os.environ['KMS_KEY'],
  )
  aws_key = 'aws-kms://' + os.environ['KMS_KEY_ID']
  return {
      'gcp': gcpkms.GcpKmsClient(gcp_key).get_aead(gcp_key),
      'aws': awskms.AwsKmsClient(aws_key, None).get_aead(aws_key),
  }


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


if __name__ == '__main__':
  aead.register()
  {'encrypt': encrypt, 'decrypt': decrypt}[sys.argv[1]]()
