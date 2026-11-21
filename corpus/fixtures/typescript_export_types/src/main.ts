import { cartTotal, type Currency } from "./cart";

const currency: Currency = "EUR";
console.log(cartTotal([{ sku: "a", qty: 1 }]), currency);
