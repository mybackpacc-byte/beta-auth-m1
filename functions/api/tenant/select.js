// functions/api/tenant/select.js
// Sets session.active_tenant_id (only if user is ACTIVE member of that tenant).

import { json, readJson, badRequest, methodNotAllowed } from "../../../src/auth/http.js";
import { requireAuthContext } from "../../../src/auth/session.js";
import { requireCsrfHeader } from "../../src/auth/csrf.js";   // adjust path per file depth

export async function onRequest({ request, env }) {
  if (request.method !== "POST") return methodNotAllowed();
const csrf = requireCsrfHeader(request);
if (csrf) return csrf;

  const ctx = await requireAuthContext(env, request);
  if (ctx instanceof Response) return ctx;

  const body = await readJson(request);
  if (!body) return badRequest("Expected JSON body.");
  const tenantId = String(body.tenant_id || "").trim();
  if (!tenantId) return badRequest("tenant_id is required.");

  const mem = await env.DB.prepare(
    `SELECT role, status
     FROM user_tenants
     WHERE user_id = ?1 AND tenant_id = ?2
     LIMIT 1`
  ).bind(ctx.user.id, tenantId).first();

  if (!mem) return json({ ok: false, error: "NOT_A_MEMBER" }, 403);
  if (mem.status !== "active") return json({ ok: false, error: "MEMBERSHIP_NOT_ACTIVE" }, 403);

  await env.DB.prepare(
    "UPDATE sessions SET active_tenant_id = ?1 WHERE id = ?2"
  ).bind(tenantId, ctx.session.id).run();

  return json({ ok: true, active_tenant_id: tenantId });
}
