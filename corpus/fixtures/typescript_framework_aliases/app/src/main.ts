export async function report() {
  const template = await import(/* webpackChunkName: "template" */ "./template");
  return template.default;
}

report();
