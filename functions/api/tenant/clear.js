// functions/api/tenant/clear.js
// Clears session.active_tenant_id so dashboard shows tenant picker again.

import { json, methodNotAllowed } from "../../../src/auth/http.js";
import { requireAuthContext } from "../../../src/auth/session.js";
import { requireCsrfHeader } from "../../../src/auth/csrf.js";

export async function onRequest({ request, env }) {
  if (request.method !== "POST") return methodNotAllowed();

  const csrf = requireCsrfHeader(request);
  if (csrf) return csrf;

  const ctx = await requireAuthContext(env, request);
  if (ctx instanceof Response) return ctx;

  await env.DB.prepare("UPDATE sessions SET active_tenant_id = NULL WHERE id = ?1")
    .bind(ctx.session.id).run();

  return json({ ok: true, active_tenant_id: null });
}
