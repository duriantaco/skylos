type User = {
  id: string;
};

type UserId = string & { readonly __brand: "UserId" };

function isUser(value: unknown): value is User {
  if (typeof value !== "object" || value === null || !("id" in value)) {
    return false;
  }
  return typeof value.id === "string";
}

export function parseUser(payload: string): User {
  const value: unknown = JSON.parse(payload);
  if (!isUser(value)) {
    throw new TypeError("Invalid user payload");
  }
  return value;
}

export function userId(value: string): UserId {
  return value as UserId;
}

// @ts-expect-error -- this fixture deliberately checks a rejected assignment
const rejectedUser: User = { id: 42 };
void rejectedUser;
