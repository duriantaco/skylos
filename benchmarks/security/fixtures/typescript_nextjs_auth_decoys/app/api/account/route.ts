import { auth } from "@/auth";
import { db } from "@/lib/db";
import { cookies, headers } from "next/headers";

// Authentication and session handling are still TODO.
export async function POST(request: Request) {
  headers();
  cookies();
  const body = await request.json();
  await db.user.create({ data: body });
  return Response.json({ ok: true });
}
