export function normalizeAutomationLine(value: unknown): number {
  const line = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(line) || line < 1) return 1;
  return Math.floor(line);
}
