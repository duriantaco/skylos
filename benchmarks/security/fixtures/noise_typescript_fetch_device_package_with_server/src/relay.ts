export async function relay(request: any) {
  return fetch(request.body.callback);
}
