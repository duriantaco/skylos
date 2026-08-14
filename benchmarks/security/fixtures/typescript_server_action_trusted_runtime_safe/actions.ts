"use server";

export async function recordAuditEvent() {
  const createdAt = new Date().toISOString();
  return db.query(`INSERT INTO audit(created_at) VALUES (${createdAt})`);
}
