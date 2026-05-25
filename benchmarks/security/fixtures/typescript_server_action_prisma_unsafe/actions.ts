"use server";

import { prisma } from "@/lib/db";

export async function findUser(formData: FormData) {
  const email = String(formData.get("email") ?? "");
  return prisma.$queryRawUnsafe(
    `SELECT id, email FROM users WHERE email = '${email}'`
  );
}
