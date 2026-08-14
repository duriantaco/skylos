"use server";

function buildQuery(text: string, value: string) {
  return { text, values: [value] };
}

export async function findUser(input: string) {
  return db.query(
    buildQuery("SELECT * FROM users WHERE name = $1", input),
  );
}
