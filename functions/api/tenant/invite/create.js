// functions/api/tenant/invite/create.js
// Admin-only: generate join codes for ACTIVE tenant.
// Important: join codes never directly grant admin.

import { json, readJson, badRequest, methodNotAllowed } from "../../../../src/auth/http.js";
import { requireAuthContext } from "../../../../src/auth/session.js";
import { requireCsrfHeader } from "../../../../src/auth/csrf.js";
import { makeJoinCode } from "../../../../src/auth/tenant.js";

const ALLOWED_ROLES = new Set(["student", "teacher"]);

export async function onRequest({ request, env }) {
  if (request.method !== "POST") return methodNotAllowed();

  const csrf = requireCsrfHeader(request);
  if (csrf) return csrf;

  const ctx = await requireAuthContext(env, request);
  if (ctx instanceof Response) return ctx;

  const tenantId = ctx.session.active_tenant_id;
  if (!tenantId) return json({ ok: false, error: "NO_ACTIVE_TENANT" }, 400);

  // must be active admin in this tenant
  const me = await env.DB.prepare(
    `SELECT role, status FROM user_tenants
     WHERE user_id = ?1 AND tenant_id = ?2 LIMIT 1`
  ).bind(ctx.user.id, tenantId).first();

  if (!me || me.status !== "active") return json({ ok: false, error: "NO_ACTIVE_MEMBERSHIP" }, 403);
  if (me.role !== "admin") return json({ ok: false, error: "ADMIN_ONLY" }, 403);

  const body = await readJson(request);
  if (!body) return badRequest("Expected JSON body.");

  const role = String(body.role || "student").toLowerCase().trim();
  if (!ALLOWED_ROLES.has(role)) return badRequest("role must be student or teacher.");

  // safer default: require approval unless explicitly turned off
  const requireApproval = body.require_approval === false ? 0 : 1;

  // optional limits
  const maxUses = body.max_uses ? Number(body.max_uses) : null;
  const expiresDays = body.expires_days ? Number(body.expires_days) : null;

  if (maxUses !== null && (!Number.isFinite(maxUses) || maxUses < 1 || maxUses > 5000)) {
    return badRequest("max_uses must be 1..5000");
  }
  if (expiresDays !== null && (!Number.isFinite(expiresDays) || expiresDays < 1 || expiresDays > 365)) {
    return badRequest("expires_days must be 1..365");
  }

  const now = Date.now();
  const expiresAt = expiresDays ? now + expiresDays * 24 * 60 * 60 * 1000 : null;

  const code = makeJoinCode("BETA");

  await env.DB.prepare(
    `INSERT INTO tenant_invites
      (code, tenant_id, default_role, require_approval, expires_at, max_uses, uses_count, created_at, created_by_user_id)
     VALUES
      (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8)`
  ).bind(code, tenantId, role, requireApproval, expiresAt, maxUses, now, ctx.user.id).run();

  return json({
    ok: true,
    invite: {
      code,
      tenant_id: tenantId,
      role,
      require_approval: !!requireApproval,
      expires_at: expiresAt,
      max_uses: maxUses
    }
  }, 201);
}
