// src/auth/db.js

export async function listTables(db) {
  const res = await db.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
  ).all();
  return (res?.results || []).map(r => r.name);
}

export async function getUserByEmail(db, email) {
  return await db.prepare(
    "SELECT id, email, password_hash, created_at FROM users WHERE email = ?1"
  ).bind(email).first();
}
