export { verifyToken } from "./token";
export type { User } from "./types";
export default function createClient() {
  return { ready: true };
}
