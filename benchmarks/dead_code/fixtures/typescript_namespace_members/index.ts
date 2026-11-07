import * as service from "./service";
import * as worker from "./worker.js";

const selected = service;
selected.format();
worker.run();

function inspect(service: { retired(): number }) {
  return service.retired();
}
inspect({ retired() { return 0; } });
