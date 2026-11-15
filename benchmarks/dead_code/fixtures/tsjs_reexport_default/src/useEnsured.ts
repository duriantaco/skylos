export default function useEnsured<T>(ref: { current: T }): { current: T } {
  return ref;
}

export function ensuredForward<T>(component: T): T {
  useEnsured({ current: component });
  return component;
}
