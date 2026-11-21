export interface CartLine {
  sku: string;
  qty: number;
}

export type LegacyLine = { sku: string };

export type Currency = "EUR" | "USD";

export const Totals = { zero: 0 };
export type Totals = typeof Totals;

/** @public */
export type PublishedLine = CartLine & { note: string };

export type LocalOnly = { cents: number };

export function cartTotal(lines: CartLine[]): number {
  const total: LocalOnly = { cents: 0 };
  for (const line of lines) total.cents += line.qty;
  return total.cents;
}
