export function verify(req: any) {
  return req.query.token === process.env.WEBHOOK_TOKEN;
}
