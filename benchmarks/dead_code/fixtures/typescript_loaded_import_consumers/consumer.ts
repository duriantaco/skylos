import {calculate, modes} from "./helpers";
export function prepare() { return calculate() + modes[0]; }
console.log(prepare());
