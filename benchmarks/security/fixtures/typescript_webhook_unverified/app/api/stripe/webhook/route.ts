type StripeEvent = {
  type: string;
  data: { object: { id: string } };
};

export async function POST(request: Request) {
  const rawBody = await request.text();
  const event = JSON.parse(rawBody) as StripeEvent;

  if (event.type === "checkout.session.completed") {
    await fulfillOrder(event.data.object.id);
  }

  return Response.json({ received: true });
}

async function fulfillOrder(sessionId: string) {
  return sessionId;
}
