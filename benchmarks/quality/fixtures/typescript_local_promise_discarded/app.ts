async function persist(): Promise<void> {
  throw new Error("disk failure");
}
export function save(): void {
  persist();
}
