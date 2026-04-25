export function runJob(name: string): string {
  return formatJob(name);
}

function formatJob(name: string): string {
  return `job:${name}`;
}

export function unusedTransform(name: string): string {
  return name.trim().toUpperCase();
}
