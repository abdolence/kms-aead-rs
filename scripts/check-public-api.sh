#!/usr/bin/env bash
# Fails when a type, trait or error of a crypto library appears in the public API of a crate, so
# that a major release of ring, aws-lc-rs or a RustCrypto crate is never a breaking change here.
#
# Needs cargo-public-api and a nightly toolchain for its rustdoc JSON:
#   rustup toolchain install nightly
#   cargo install cargo-public-api --locked
#
# Usage: scripts/check-public-api.sh [package], kms-aead by default.
set -euo pipefail

package="${1:-kms-aead}"

case "$package" in
  kms-aead)
    features="ring,legacy-formats,serde,gcp-kms-encryption,aws-kms-encryption,azure-kms-encryption,vault-transit-kms-encryption"
    ;;
  *)
    echo "No feature set for package $package" >&2
    exit 2
    ;;
esac

# Blanket impls stay in the output, so that trait bounds and `From` impls are matched too.
# `kms_aead::` does not match `\baead::`, since `_` and `a` are both word characters.
crypto_paths='\b(ring|aws_lc_rs|aws_lc_sys|aws_lc_fips_sys|aes_gcm|aes_gcm_siv|chacha20poly1305|aes_siv|aead|getrandom|rand_core)::'

api="$(cargo public-api --package "$package" --features "$features")"

if leaks="$(grep -E "$crypto_paths" <<<"$api")"; then
  echo "The public API of $package names a crypto library:" >&2
  echo "$leaks" >&2
  exit 1
fi

echo "The public API of $package names no crypto library ($(wc -l <<<"$api") items checked)"
