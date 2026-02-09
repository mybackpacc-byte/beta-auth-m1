// functions/api/tenant/approve.js
// Admin-only: approve a pending member in the ACTIVE tenant.

import { json, readJson, badRequest, methodNotAllowed } from "../../../src/auth/http.js";
import { requireAuthContext } from "../../../src/auth/session.js";

export async function onRequest({ request, env }) {
  if (request.method !== "POST") return methodNotAllowed();

  const ctx = await requireAuthContext(env, request);
  if (ctx instanceof Response) return ctx;

  const tenantId = ctx.session.active_tenant_id;
  if (!tenantId) return json({ ok: false, error: "NO_ACTIVE_TENANT" }, 400);

  const me = await env.DB.prepare(
    `SELECT role, status
     FROM user_tenants
     WHERE user_id = ?1 AND tenant_id = ?2
     LIMIT 1`
  ).bind(ctx.user.id, tenantId).first();

  if (!me || me.status !== "active") return json({ ok: false, error: "NO_ACTIVE_MEMBERSHIP" }, 403);
  if (me.role !== "admin") return json({ ok: false, error: "ADMIN_ONLY" }, 403);

  const body = await readJson(request);
  if (!body) return badRequest("Expected JSON body.");
  const userId = String(body.user_id || "").trim();
  if (!userId) return badRequest("user_id is required.");

  const r = await env.DB.prepare(
    `UPDATE user_tenants
     SET status = 'active'
     WHERE tenant_id = ?1 AND user_id = ?2 AND status = 'pending'`
  ).bind(tenantId, userId).run();

  return json({ ok: true, approved: r?.meta?.changes ? true : false });
}
