// src/auth/session.js
// Central auth guard used by tenant endpoints.
// Keeps logic consistent: cookie -> token_hmac -> session row -> user row.
// If session is expired, we also delete it (light cleanup).

import { serverError, unauthorized } from "./http.js";
import { parseCookies, SESSION_COOKIE } from "./cookies.js";
import { hmacSha256Base64Url } from "./crypto.js";

/**
 * Returns either:
 *  - Response (error)
 *  - { user: {id,email}, session: {id,user_id,expires_at,active_tenant_id} }
 */
export async function requireAuthContext(env, request) {
  if (!env?.DB) return serverError("DB binding missing (bind D1 as variable name DB).");
  if (!env?.SESSION_SECRET) return serverError("SESSION_SECRET missing (set in Pages → Variables/Secrets).");

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const token = cookies[SESSION_COOKIE];
  if (!token) return unauthorized("No session.");

  const tokenHmac = await hmacSha256Base64Url(env.SESSION_SECRET, token);

  const row = await env.DB.prepare(
    `SELECT
       s.id          AS session_id,
       s.user_id     AS user_id,
       s.expires_at  AS expires_at,
       s.active_tenant_id AS active_tenant_id,
       u.email       AS email
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hmac = ?1
     LIMIT 1`
  ).bind(tokenHmac).first();

  if (!row) return unauthorized("Invalid session.");

  const now = Date.now();
  if (Number(row.expires_at) <= now) {
    // clean up expired session row
    await env.DB.prepare("DELETE FROM sessions WHERE id = ?1").bind(row.session_id).run();
    return unauthorized("Session expired.");
  }

  return {
    user: { id: row.user_id, email: row.email },
    session: {
      id: row.session_id,
      user_id: row.user_id,
      expires_at: Number(row.expires_at),
      active_tenant_id: row.active_tenant_id || null,
    }
  };
}
