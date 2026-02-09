// src/auth/crypto.js
// Web Crypto helpers: PBKDF2 password hashing + HMAC for session tokens.

const PBKDF2_ITERS = 100000; // reasonable balance for Workers/Pages runtime
const PBKDF2_HASH = "SHA-256";
const DERIVED_KEY_BITS = 256; // 32 bytes

function bytesToBase64(bytes) {
  // Convert Uint8Array -> base64 using chunking to avoid call stack limits
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function base64ToBytes(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function base64UrlEncode(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlDecodeToBytes(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
  return base64ToBytes(b64);
}

export function utf8ToBytes(str) {
  return new TextEncoder().encode(str);
}

export function bytesToUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

export function randomBase64Url(byteLen = 32) {
  const buf = new Uint8Array(byteLen);
  crypto.getRandomValues(buf);
  return base64UrlEncode(buf);
}

async function pbkdf2Bits(password, saltBytes, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    utf8ToBytes(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: PBKDF2_HASH },
    keyMaterial,
    DERIVED_KEY_BITS
  );

  return new Uint8Array(bits);
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a[i] ^ b[i];
  return out === 0;
}

/**
 * Stored format:
 * pbkdf2_sha256$<iters>$<salt_b64url>$<hash_b64url>
 */
export async function hashPassword(password) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const hashBytes = await pbkdf2Bits(password, salt, PBKDF2_ITERS);

  const saltB64u = base64UrlEncode(salt);
  const hashB64u = base64UrlEncode(hashBytes);

  return `pbkdf2_sha256$${PBKDF2_ITERS}$${saltB64u}$${hashB64u}`;
}

export async function verifyPassword(password, stored) {
  try {
    const parts = String(stored).split("$");
    if (parts.length !== 4) return false;
    const [alg, itersStr, saltB64u, hashB64u] = parts;
    if (alg !== "pbkdf2_sha256") return false;

    const iters = Number(itersStr);
    if (!Number.isFinite(iters) || iters < 50000) return false;

    const salt = base64UrlDecodeToBytes(saltB64u);
    const expected = base64UrlDecodeToBytes(hashB64u);

    const actual = await pbkdf2Bits(password, salt, iters);
    return constantTimeEqual(actual, expected);
  } catch {
    return false;
  }
}

export async function hmacSha256Base64Url(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    utf8ToBytes(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, utf8ToBytes(data));
  return base64UrlEncode(new Uint8Array(sig));
}
