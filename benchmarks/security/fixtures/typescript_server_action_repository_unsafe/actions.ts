"use server";

class UserRepository {
  lookup(value: string) {
    const query = "SELECT * FROM users WHERE name = '" + value + "'";
    return db.query(query);
  }
}

const repository = new UserRepository();

export async function findUser(input: string) {
  return repository.lookup(input);
}
