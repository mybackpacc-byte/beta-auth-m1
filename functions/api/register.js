// functions/api/register.js
import { json, readJson, badRequest, methodNotAllowed, serverError } from "../../src/auth/http.js";
import { hashPassword } from "../../src/auth/crypto.js";
import { requireCsrfHeader } from "../../src/auth/csrf.js";   // adjust path per file depth

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function looksLikeEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export async function onRequest({ request, env }) {
  if (request.method !== "POST") return methodNotAllowed();
  if (!env?.DB) return serverError("DB binding missing (bind D1 as variable name DB).");
const csrf = requireCsrfHeader(request);
if (csrf) return csrf;

  const body = await readJson(request);
  if (!body) return badRequest("Expected JSON body.");

  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  if (!email || !looksLikeEmail(email)) return badRequest("Invalid email.");
  if (password.length < 8) return badRequest("Password must be at least 8 characters.");

  const userId = crypto.randomUUID();
let passwordHash;
try {
  passwordHash = await hashPassword(password);
} catch (e) {
  console.error("hashPassword failed:", e);
  return serverError("Password hashing failed (PBKDF2).");
}
  const createdAt = Date.now();

  try {
    await env.DB.prepare(
      "INSERT INTO users (id, email, password_hash, created_at) VALUES (?1, ?2, ?3, ?4)"
    ).bind(userId, email, passwordHash, createdAt).run();

    return json({ ok: true, user: { id: userId, email } }, 201);
  } catch (e) {
    const msg = String(e?.message || e);
    if (msg.includes("UNIQUE") || msg.includes("constraint")) {
      return json({ ok: false, error: "EMAIL_EXISTS" }, 409);
    }
    return serverError(msg);
  }
}
