// src/auth/http.js

export function json(data, status = 200, extraHeaders = {}) {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...extraHeaders,
  };
  return new Response(JSON.stringify(data, null, 2), { status, headers });
}

export async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

export function methodNotAllowed() {
  return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
}

export function badRequest(message = "BAD_REQUEST") {
  return json({ ok: false, error: "BAD_REQUEST", message }, 400);
}

export function unauthorized(message = "UNAUTHORIZED") {
  return json({ ok: false, error: "UNAUTHORIZED", message }, 401);
}

export function serverError(message = "SERVER_ERROR") {
  return json({ ok: false, error: "SERVER_ERROR", message }, 500);
}
