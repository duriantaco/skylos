import * as service from "./service";
import * as dynamic from "./dynamic";

globalThis.consume(service);
dynamic[process.argv[2]]();

function staleHelper() { return "legacy"; }
