import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request) {
  const signature = request.headers.get("stripe-signature");
  if (!signature) {
    return Response.json({ error: "missing signature" }, { status: 400 });
  }

  const rawBody = await request.text();
  const event = stripe.webhooks.constructEvent(
    rawBody,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET!
  );

  return Response.json({ type: event.type });
}
