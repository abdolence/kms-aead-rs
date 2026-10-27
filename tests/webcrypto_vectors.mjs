// Run with `node tests/webcrypto_vectors.mjs` (Node 24); it exits non-zero on a mismatch.

// The verifier of docs/src/signing.md, "In a browser", as published there.

async function verifyDetached(jwks, payloadType, payload, signature) {
  if (signature.length < 6 || signature[0] !== 0x01) {
    throw new Error("not a detached signature");
  }
  const keyId = new DataView(signature.buffer, signature.byteOffset, 5).getUint32(1);
  const raw = signature.subarray(5);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", payload));
  const preImage = pae(payloadType, digest);
  const jwk = await keyWithId(jwks, keyId);
  if (jwk === null || raw.length !== 64) return null;
  const [importParams, verifyParams] = algorithmOf(jwk);
  const key = await crypto.subtle.importKey("jwk", jwk, importParams, false, ["verify"]);
  const verified = await crypto.subtle.verify(verifyParams, key, raw, preImage);
  return verified ? jwk : null;
}

async function keyWithId(jwks, keyId) {
  for (const jwk of jwks.keys) {
    if ((await keyIdOf(jwk)) === keyId) return jwk;
  }
  return null;
}

function pae(payloadType, body) {
  const ascii = new TextEncoder();
  const type = ascii.encode(payloadType);
  const head = ascii.encode(`DSSEv1 ${type.length} `);
  const middle = ascii.encode(` ${body.length} `);
  const out = new Uint8Array(head.length + type.length + middle.length + body.length);
  out.set(head, 0);
  out.set(type, head.length);
  out.set(middle, head.length + type.length);
  out.set(body, head.length + type.length + middle.length);
  return out;
}

function algorithmOf(jwk) {
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
    return [{ name: "Ed25519" }, { name: "Ed25519" }];
  }
  if (jwk.kty === "EC" && jwk.crv === "P-256") {
    return [{ name: "ECDSA", namedCurve: "P-256" }, { name: "ECDSA", hash: "SHA-256" }];
  }
  throw new Error("unsupported key");
}

async function keyIdOf(jwk) {
  if (Number.isInteger(jwk.kms_aead_key_id)) return jwk.kms_aead_key_id;
  const members =
    jwk.kty === "OKP"
      ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x }
      : { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  const input = new TextEncoder().encode(JSON.stringify(members));
  const digest = await crypto.subtle.digest("SHA-256", input);
  return new DataView(digest).getUint32(0);
}

// The vectors of docs/src/formats.md, "Signature and MAC test vectors".

const PAYLOAD_TYPE = "application/vnd.example.invoice+json";
const PAYLOAD_TEXT =
  '{"number":"INV-1042","customer":"Northwind Traders","currency":"EUR","total_cents":12500}';
const PAYLOAD = new TextEncoder().encode(PAYLOAD_TEXT);

const ED25519_JWK = {
  kty: "OKP",
  crv: "Ed25519",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
  kid: "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
  use: "sig",
  alg: "EdDSA",
};
const P256_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y",
  y: "eQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk",
  kid: "DOvxvJiAdIqVWIkFt5hDtCunXLF0BV4-JGv4f-ALSm0",
  use: "sig",
  alg: "ES256",
};
const JWKS = { keys: [ED25519_JWK, P256_JWK] };

const ED25519_KEY_ID = 0x90facafe;
const P256_KEY_ID = 0x0cebf1bc;
const ED25519_SIGNATURE =
  "21c5f4d55977b19640f25f0e248d4c9765aa0d210f9c781b61b46dece74d4dec" +
  "b950acf3947659a9fff322b88ad8562e2c9ee4392440a4da901b7fec385f1102";
const P256_SIGNATURE =
  "409b9927a7f27d61f6d7360b9b91941fa6dd14db553a55d0dd573fc9db7fccb7" +
  "af3a4aaab89c0684256afe5db6aa53e4569286bc2c2f6435fe7563db215b5976";

const PRE_IMAGE_HEX =
  "445353457631203336206170706c69636174696f6e2f766e642e6578616d706c652e" +
  "696e766f6963652b6a736f6e203332207b43154b748a12c6909cba38acd83fff12a1" +
  "1b6345effb807b21c7ce465e4cd1";
const PAYLOAD_DIGEST_HEX = "7b43154b748a12c6909cba38acd83fff12a11b6345effb807b21c7ce465e4cd1";
const PRE_IMAGE_DIGEST_HEX = "4617fb02679fc4831b071fb2a064a33c2999e5f6a3c2fb65a96474d5663950be";

const failures = [];
function check(name, holds) {
  if (!holds) failures.push(name);
}

function fromHex(hex) {
  return Uint8Array.from(hex.match(/../g) ?? [], (byte) => parseInt(byte, 16));
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function header(keyId) {
  const out = new Uint8Array(5);
  out[0] = 0x01;
  new DataView(out.buffer).setUint32(1, keyId);
  return out;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function base64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

const digest = await sha256(PAYLOAD);
check("SHA-256 of the payload", toHex(digest) === PAYLOAD_DIGEST_HEX);
const preImage = pae(PAYLOAD_TYPE, digest);
check("pre-image", toHex(preImage) === PRE_IMAGE_HEX && preImage.length === 82);
check("SHA-256 of the pre-image", toHex(await sha256(preImage)) === PRE_IMAGE_DIGEST_HEX);

// Key ids and thumbprints.
check("Ed25519 key id from the JWK Set", (await keyIdOf(ED25519_JWK)) === ED25519_KEY_ID);
check("P-256 key id from the JWK Set", (await keyIdOf(P256_JWK)) === P256_KEY_ID);
for (const jwk of JWKS.keys) {
  const members =
    jwk.kty === "OKP"
      ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x }
      : { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  const thumbprint = await sha256(new TextEncoder().encode(JSON.stringify(members)));
  check(`${jwk.crv} kid is the base64url thumbprint`, base64url(thumbprint) === jwk.kid);
}
const PUBLISHER_KEY_ID = 4242;
const SET_KEY_ID = { ...ED25519_JWK, kms_aead_key_id: PUBLISHER_KEY_ID };
check("kms_aead_key_id overrides the derived id", (await keyIdOf(SET_KEY_ID)) === PUBLISHER_KEY_ID);
check(
  "kms_aead_key_id of 0 is an id",
  (await keyIdOf({ ...ED25519_JWK, kms_aead_key_id: 0 })) === 0,
);
check(
  "a kms_aead_key_id that is not an integer is ignored",
  (await keyIdOf({ ...ED25519_JWK, kms_aead_key_id: "4242" })) === ED25519_KEY_ID,
);

// Detached values.
const ed25519Detached = concat(header(ED25519_KEY_ID), fromHex(ED25519_SIGNATURE));
check("detached Ed25519 layout", ed25519Detached.length === 69);
check(
  "detached Ed25519 verifies",
  (await verifyDetached(JWKS, PAYLOAD_TYPE, PAYLOAD, ed25519Detached)) === ED25519_JWK,
);
const p256Detached = concat(header(P256_KEY_ID), fromHex(P256_SIGNATURE));
check("detached P-256 layout", p256Detached.length === 69);
check(
  "detached P-256 verifies",
  (await verifyDetached(JWKS, PAYLOAD_TYPE, PAYLOAD, p256Detached)) === P256_JWK,
);

// Attached Ed25519 value: the signature is the `w` bytes after the u16 at bytes 5 and 6.
const attached = concat(
  header(ED25519_KEY_ID),
  Uint8Array.of(0x00, 0x40),
  fromHex(ED25519_SIGNATURE),
  PAYLOAD,
);
check("attached Ed25519 layout", attached.length === 160);
const width = new DataView(attached.buffer, attached.byteOffset, attached.length).getUint16(5);
const attachedSignature = attached.subarray(7, 7 + width);
const attachedPayload = attached.subarray(7 + width);
check(
  "attached Ed25519 verifies",
  (await verifyDetached(
    JWKS,
    PAYLOAD_TYPE,
    attachedPayload,
    concat(attached.subarray(0, 5), attachedSignature),
  )) === ED25519_JWK,
);

// Refusals.
check(
  "another payload does not verify",
  (await verifyDetached(JWKS, PAYLOAD_TYPE, new TextEncoder().encode(PAYLOAD_TEXT.replace("12500", "99900")), ed25519Detached)) === null,
);
check(
  "another payload type does not verify",
  (await verifyDetached(JWKS, "application/json", PAYLOAD, ed25519Detached)) === null,
);
const flipped = Uint8Array.from(ed25519Detached);
flipped[40] ^= 0x01;
check("a flipped signature bit does not verify", (await verifyDetached(JWKS, PAYLOAD_TYPE, PAYLOAD, flipped)) === null);
check(
  "an id the set lacks is a refusal",
  (await verifyDetached(JWKS, PAYLOAD_TYPE, PAYLOAD, concat(header(1), fromHex(ED25519_SIGNATURE)))) === null,
);

// A key set that maps the publisher's id to the key verifies a value that carries that id, and
// no longer one that carries the derived id.
const publisherSet = { keys: [SET_KEY_ID, P256_JWK] };
check(
  "a value under the publisher's id verifies",
  (await verifyDetached(publisherSet, PAYLOAD_TYPE, PAYLOAD, concat(header(PUBLISHER_KEY_ID), fromHex(ED25519_SIGNATURE)))) === SET_KEY_ID,
);
check(
  "the derived id of a key with a publisher's id is a refusal",
  (await verifyDetached(publisherSet, PAYLOAD_TYPE, PAYLOAD, ed25519Detached)) === null,
);

if (failures.length > 0) {
  console.error(`${failures.length} check(s) failed:\n${failures.join("\n")}`);
  process.exit(1);
}
console.log("all WebCrypto vector checks passed");
