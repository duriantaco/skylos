async function persist(): Promise<void> {
  throw new Error("disk failure");
}
export async function save(): Promise<void> {
  await persist();
}
export function queue(): Promise<void> {
  return persist();
}
export function schedule(): void {
  persist().catch(console.error);
  void persist();
}
