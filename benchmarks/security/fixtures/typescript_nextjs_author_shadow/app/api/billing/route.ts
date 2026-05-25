import { db } from "@/lib/db";

export async function POST(request: Request) {
  const body = await request.json();
  const authorId = String(body.authorId ?? "");
  const plan = String(body.plan ?? "free");

  await db.billingPlan.update({
    where: { accountId: body.accountId },
    data: { authorId, plan },
  });

  return Response.json({ ok: true });
}
