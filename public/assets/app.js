// public/assets/app.js
// Shared UI helpers for Milestone 1.5 (cookie-based auth)

export function qs(name) {
  return new URLSearchParams(location.search).get(name);
}

export function setMsg(el, type, text) {
  if (!el) return;
  el.className = "msg " + (type === "ok" ? "ok" : "err");
  el.textContent = text || "";
}

export async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
+     "X-Requested-With": "Beta",
      ...(opts.headers || {})
    },
    credentials: "include",
  });


  let data = null;
  try { data = await res.json(); }
  catch { data = { ok: false, error: "NON_JSON_RESPONSE" }; }

  return { status: res.status, data };
}

export function go(url) {
  location.replace(url);
}

export function nextOr(defaultUrl) {
  const n = qs("next");
  if (!n) return defaultUrl;
  // Only allow same-site relative paths for safety
  if (n.startsWith("/") && !n.startsWith("//")) return n;
  return defaultUrl;
}

export async function requireAuth({ onAuthed, onFailRedirect = "/login.html" } = {}) {
  const { status, data } = await api("/api/me", { method: "GET" });
  if (status === 200 && data?.ok && data?.user) {
    onAuthed && onAuthed(data.user);
    return;
  }
  const here = location.pathname + location.search;
  go(`${onFailRedirect}?next=${encodeURIComponent(here)}`);
}

export function prettyErr(status, data) {
  // backend returns {ok:false, error, message?}
  if (data?.message) return data.message;
  if (data?.error === "EMAIL_EXISTS") return "That email is already registered. Try logging in.";
  if (status === 401) return "Invalid email or password.";
  if (status === 400) return "Please check the form and try again.";
  if (status >= 500) return "Server error. Try again in a moment.";
  return "Something went wrong.";
}
