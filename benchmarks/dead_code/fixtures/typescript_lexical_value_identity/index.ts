import {format, callback} from "./helpers";

function start() {
  const measure = 1;
  const saved = callback;
  console.log(measure, format(), saved());
}

start();
