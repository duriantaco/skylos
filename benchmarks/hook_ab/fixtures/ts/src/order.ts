export interface LineItem {
  sku: string;
  qty: number;
  price: number;
}

export interface Order {
  id: string;
  customer: { name: string; email: string };
  items: LineItem[];
}

export function orderTotal(order: Order): number {
  return order.items.reduce((sum, item) => sum + item.qty * item.price, 0);
}
