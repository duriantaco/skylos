import { getServerSession } from "next-auth";
import { db } from "@/lib/db";

export async function POST(request: Request) {
  const session = await getServerSession();
  if (!session) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  await db.billingPlan.update({
    where: { accountId: session.user.accountId },
    data: { plan: String(body.plan ?? "free") },
  });

  return Response.json({ ok: true });
}
