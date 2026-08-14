import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request) {
  const payload = await request.text();
  const signature = request.headers.get("stripe-signature");

  await enqueueStripeEvent(JSON.parse(payload));
  stripe.webhooks.constructEvent(
    "unrelated-payload",
    signature,
    process.env.STRIPE_WEBHOOK_SECRET!,
  );

  return new Response("ok");
}

async function enqueueStripeEvent(event: unknown) {
  return event;
}
