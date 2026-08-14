import { auth } from "@/auth";

export async function POST(request: Request) {
  const session = await auth();
  if (!session) {
    return new Response("unauthorized", { status: 401 });
  }

  await db.account.update({
    where: { id: session.user.id },
    data: await request.json(),
  });
  return Response.json({ ok: true });
}
