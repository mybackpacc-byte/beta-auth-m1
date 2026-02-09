// functions/api/tenant/create.js
// Creates a tenant, makes creator ADMIN, sets active tenant, and creates a default join code.

import { json, readJson, badRequest, methodNotAllowed } from "../../../src/auth/http.js";
import { requireAuthContext } from "../../../src/auth/session.js";
import { makeJoinCode } from "../../../src/auth/tenant.js";
import { requireCsrfHeader } from "../../src/auth/csrf.js";   // adjust path per file depth

export async function onRequest({ request, env }) {
  if (request.method !== "POST") return methodNotAllowed();
const csrf = requireCsrfHeader(request);
if (csrf) return csrf;

  const ctx = await requireAuthContext(env, request);
  if (ctx instanceof Response) return ctx;

  const body = await readJson(request);
  if (!body) return badRequest("Expected JSON body.");

  const name = String(body.name || "").trim();
  if (!name || name.length < 2) return badRequest("Tenant name must be at least 2 characters.");

  // Safer default: require admin approval for join code
  const requireApproval = body.require_approval === false ? 0 : 1;

  const tenantId = crypto.randomUUID();
  const now = Date.now();

  // Create tenant + membership + invite code
  const membershipId = crypto.randomUUID();
  const inviteCode = makeJoinCode("BETA");

  await env.DB.prepare(
    "INSERT INTO tenants (id, name, created_at, created_by_user_id) VALUES (?1, ?2, ?3, ?4)"
  ).bind(tenantId, name, now, ctx.user.id).run();

  await env.DB.prepare(
    `INSERT INTO user_tenants (id, user_id, tenant_id, role, status, created_at)
     VALUES (?1, ?2, ?3, 'admin', 'active', ?4)`
  ).bind(membershipId, ctx.user.id, tenantId, now).run();

  await env.DB.prepare(
    `INSERT INTO tenant_invites
       (code, tenant_id, default_role, require_approval, created_at, created_by_user_id)
     VALUES (?1, ?2, 'student', ?3, ?4, ?5)`
  ).bind(inviteCode, tenantId, requireApproval, now, ctx.user.id).run();

  // Set active tenant on this session immediately
  await env.DB.prepare(
    "UPDATE sessions SET active_tenant_id = ?1 WHERE id = ?2"
  ).bind(tenantId, ctx.session.id).run();

  return json({
    ok: true,
    tenant: { id: tenantId, name },
    invite: { code: inviteCode, require_approval: !!requireApproval }
  }, 201);
}
