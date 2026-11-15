export async function http(url: string, params?: Record<string, string>) {
  let fullUrl = url;
  if (params) {
    fullUrl += "?" + new URLSearchParams(params).toString();
  }
  return fetch(fullUrl);
}
