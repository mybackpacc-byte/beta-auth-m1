// functions/api/login.js
import { json, readJson, badRequest, methodNotAllowed, unauthorized, serverError } from "../../src/auth/http.js";
import { getUserByEmail } from "../../src/auth/db.js";
import { verifyPassword, randomBase64Url, hmacSha256Base64Url } from "../../src/auth/crypto.js";
import { makeSessionSetCookie } from "../../src/auth/cookies.js";
import { requireCsrfHeader } from "../../src/auth/csrf.js";   // adjust path per file depth

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

export async function onRequest({ request, env }) {
  if (request.method !== "POST") return methodNotAllowed();
  if (!env?.DB) return serverError("DB binding missing (bind D1 as variable name DB).");
  if (!env?.SESSION_SECRET) return serverError("SESSION_SECRET missing (set in Pages → Variables/Secrets).");
  const csrf = requireCsrfHeader(request);
if (csrf) return csrf;

  const body = await readJson(request);
  if (!body) return badRequest("Expected JSON body.");

  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  if (!email || !password) return badRequest("Email + password required.");

  const user = await getUserByEmail(env.DB, email);
  if (!user) return unauthorized("Invalid credentials.");

  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) return unauthorized("Invalid credentials.");

  // Create session
  const token = randomBase64Url(32); // store only in cookie
  const tokenHmac = await hmacSha256Base64Url(env.SESSION_SECRET, token);

  const sessionId = crypto.randomUUID();
  const createdAt = Date.now();
  const maxAgeSec = 60 * 60 * 24 * 7; // 7 days
  const expiresAt = createdAt + maxAgeSec * 1000;

  await env.DB.prepare(
    "INSERT INTO sessions (id, user_id, token_hmac, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)"
  ).bind(sessionId, user.id, tokenHmac, createdAt, expiresAt).run();

  const setCookie = makeSessionSetCookie(token, maxAgeSec);

  return json(
    { ok: true, user: { id: user.id, email: user.email } },
    200,
    { "Set-Cookie": setCookie }
  );
}
