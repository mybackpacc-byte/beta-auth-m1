// src/auth/tenant.js
// Tenant helpers: join-code normalization + human-friendly code generation.
// Codes avoid confusing characters (I,O,0,1).

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export function normalizeJoinCode(code) {
  return String(code || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "");
}

export function makeJoinCode(prefix = "BETA") {
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);

  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += ALPHABET[bytes[i] % ALPHABET.length];
  }

  // Example: BETA-K7QW9M
  return `${prefix}-${out}`;
}
