// src/auth/csrf.js
// CSRF protection for cookie-based auth.
// Rule: all state-changing requests must include a custom header.
// Browsers cannot add custom headers cross-site without a preflight, so CSRF is blocked.

import { json } from "./http.js";

export function requireCsrfHeader(request) {
  const v = request.headers.get("X-Requested-With");
  if (v !== "Beta") {
    return json({ ok: false, error: "CSRF_BLOCKED", message: "Missing CSRF header." }, 403);
  }
  return null;
}
