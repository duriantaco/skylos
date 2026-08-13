"use server";

import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export async function findUser(email: string) {
  return prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;
}
