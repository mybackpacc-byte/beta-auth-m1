// functions/api/tenant/join.js
// Join a tenant using a join code. If require_approval=1 => status=pending.

import { json, readJson, badRequest, methodNotAllowed } from "../../../src/auth/http.js";
import { requireAuthContext } from "../../../src/auth/session.js";
import { normalizeJoinCode } from "../../../src/auth/tenant.js";
import { requireCsrfHeader } from "../../src/auth/csrf.js";   // adjust path per file depth

export async function onRequest({ request, env }) {
  if (request.method !== "POST") return methodNotAllowed();
const csrf = requireCsrfHeader(request);
if (csrf) return csrf;

  const ctx = await requireAuthContext(env, request);
  if (ctx instanceof Response) return ctx;

  const body = await readJson(request);
  if (!body) return badRequest("Expected JSON body.");

  const code = normalizeJoinCode(body.code);
  if (!code) return badRequest("Join code is required.");

  const invite = await env.DB.prepare(
    `SELECT code, tenant_id, default_role, require_approval, expires_at, max_uses, uses_count
     FROM tenant_invites
     WHERE code = ?1
     LIMIT 1`
  ).bind(code).first();

  if (!invite) return json({ ok: false, error: "CODE_NOT_FOUND" }, 404);

  const now = Date.now();
  if (invite.expires_at && Number(invite.expires_at) <= now) {
    return json({ ok: false, error: "CODE_EXPIRED" }, 410);
  }
  if (invite.max_uses && Number(invite.uses_count) >= Number(invite.max_uses)) {
    return json({ ok: false, error: "CODE_MAX_USES_REACHED" }, 410);
  }

  // If already a member, return current membership (do NOT consume a use)
  const existing = await env.DB.prepare(
    `SELECT tenant_id, role, status
     FROM user_tenants
     WHERE user_id = ?1 AND tenant_id = ?2
     LIMIT 1`
  ).bind(ctx.user.id, invite.tenant_id).first();

  if (existing) {
    return json({ ok: true, membership: existing, already_member: true });
  }

  const status = Number(invite.require_approval) === 1 ? "pending" : "active";
  const role = String(invite.default_role || "student");
  const memId = crypto.randomUUID();

  await env.DB.prepare(
    `INSERT INTO user_tenants (id, user_id, tenant_id, role, status, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
  ).bind(memId, ctx.user.id, invite.tenant_id, role, status, now).run();

  // consume a use
  await env.DB.prepare(
    "UPDATE tenant_invites SET uses_count = uses_count + 1 WHERE code = ?1"
  ).bind(code).run();

  // If ACTIVE immediately, set active tenant on session
  if (status === "active") {
    await env.DB.prepare(
      "UPDATE sessions SET active_tenant_id = ?1 WHERE id = ?2"
    ).bind(invite.tenant_id, ctx.session.id).run();
  }

  return json({
    ok: true,
    membership: { tenant_id: invite.tenant_id, role, status },
    pending: status === "pending"
  }, 200);
}
