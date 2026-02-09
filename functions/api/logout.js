// functions/api/logout.js
import { json, methodNotAllowed } from "../../src/auth/http.js";
import { parseCookies, SESSION_COOKIE, clearSessionSetCookie } from "../../src/auth/cookies.js";
import { hmacSha256Base64Url } from "../../src/auth/crypto.js";
import { requireCsrfHeader } from "../../src/auth/csrf.js";   // adjust path per file depth

export async function onRequest({ request, env }) {
  if (request.method !== "POST") return methodNotAllowed();
const csrf = requireCsrfHeader(request);
if (csrf) return csrf;

  const setCookie = clearSessionSetCookie();

  // If DB/secret missing, still clear cookie and return ok.
  if (!env?.DB || !env?.SESSION_SECRET) {
    return json({ ok: true }, 200, { "Set-Cookie": setCookie });
  }

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const token = cookies[SESSION_COOKIE];

  if (token) {
    const tokenHmac = await hmacSha256Base64Url(env.SESSION_SECRET, token);
    await env.DB.prepare("DELETE FROM sessions WHERE token_hmac = ?1").bind(tokenHmac).run();
  }

  return json({ ok: true }, 200, { "Set-Cookie": setCookie });
}
