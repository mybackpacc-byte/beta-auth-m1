// functions/api/me.js
import { json, methodNotAllowed, unauthorized, serverError } from "../../src/auth/http.js";
import { parseCookies, SESSION_COOKIE } from "../../src/auth/cookies.js";
import { hmacSha256Base64Url } from "../../src/auth/crypto.js";

export async function onRequest({ request, env }) {
  if (request.method !== "GET") return methodNotAllowed();
  if (!env?.DB) return serverError("DB binding missing (bind D1 as variable name DB).");
  if (!env?.SESSION_SECRET) return serverError("SESSION_SECRET missing (set in Pages → Variables/Secrets).");

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const token = cookies[SESSION_COOKIE];
  if (!token) return unauthorized("No session.");

  const tokenHmac = await hmacSha256Base64Url(env.SESSION_SECRET, token);

  const now = Date.now();
  const row = await env.DB.prepare(
    `SELECT s.user_id, s.expires_at, u.email
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hmac = ?1
     LIMIT 1`
  ).bind(tokenHmac).first();

  if (!row) return unauthorized("Invalid session.");
  if (Number(row.expires_at) <= now) return unauthorized("Session expired.");

  return json({
    ok: true,
    user: { id: row.user_id, email: row.email }
  });
}
