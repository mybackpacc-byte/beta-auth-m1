// functions/api/health.js
import { json } from "../../src/auth/http.js";
import { listTables } from "../../src/auth/db.js";

export async function onRequest({ env }) {
  const runtime = "cloudflare-pages-functions";

  const hasDB = !!env?.DB;
  let tables = [];
  let dbOk = false;
  let dbError = null;

  if (hasDB) {
    try {
      tables = await listTables(env.DB);
      dbOk = true;
    } catch (e) {
      dbOk = false;
      dbError = String(e?.message || e);
    }
  }

  return json({
    ok: true,
    runtime,
    env: { DB: hasDB ? "OK" : "MISSING" },
    db: { ok: dbOk, error: dbError, tables }
  });
}
