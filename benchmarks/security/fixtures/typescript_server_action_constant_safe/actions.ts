"use server";

const table = "users";
const limit = 25;

export async function listUsers() {
  return db.query(`SELECT * FROM ${table} LIMIT ${limit}`);
}
