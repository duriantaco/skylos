import otherUrl from "./runtime-config";

export async function loadOther() {
  return fetch(otherUrl);
}
