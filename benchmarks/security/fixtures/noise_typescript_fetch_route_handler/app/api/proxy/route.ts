export async function GET(request: Request) {
  const target = new URL(request.url).searchParams.get("target");
  return fetch(target!);
}
