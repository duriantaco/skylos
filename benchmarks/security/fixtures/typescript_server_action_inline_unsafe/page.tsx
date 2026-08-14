export async function findUser(email: string) {
  "use server";
  return db.query(`SELECT * FROM users WHERE email = '${email}'`);
}
