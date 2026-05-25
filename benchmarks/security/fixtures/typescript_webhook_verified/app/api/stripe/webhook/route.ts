import Stripe from "stripe";

const stripe = new Stripe(loadStripeApiKeyForFixture());

export async function POST(request: Request) {
  const signature = request.headers.get("stripe-signature");
  if (!signature) {
    return Response.json({ error: "missing signature" }, { status: 400 });
  }

  const rawBody = await request.text();
  const event = stripe.webhooks.constructEvent(
    rawBody,
    signature,
    loadStripeWebhookKeyForFixture()
  );

  return Response.json({ type: event.type });
}

function loadStripeApiKeyForFixture() {
  return "fixture_api_key";
}

function loadStripeWebhookKeyForFixture() {
  return "fixture_webhook_key";
}
