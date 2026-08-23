type User = {
  id: string;
};

declare const input: unknown;
declare const payload: string;

export const forcedUser = input as unknown as User;

// @ts-ignore -- the generated SDK type was not checked
export const ignoredTypeError: string = 1;

export const parsedUser = JSON.parse(payload) as User;
