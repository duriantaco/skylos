export {};

enum Status {
  Ready = "ready",
  Spare = "spare"
}

console.log(Status.Ready);

enum Escaping {
  Active = "active",
  Idle = "idle"
}

function inspect(value: unknown) {
  console.log(value);
}

inspect(Escaping);

export enum PublicStatus {
  Current = "current",
  Legacy = "legacy"
}
