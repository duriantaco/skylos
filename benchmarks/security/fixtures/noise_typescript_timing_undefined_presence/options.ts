export function requestOptions(auth: { apiKey?: string }) {
  return {
    ...(auth.apiKey === undefined ? {} : { apiKey: auth.apiKey }),
  };
}
