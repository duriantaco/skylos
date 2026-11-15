import wasmUrl from "./codec.wasm?url";

export async function loadCodec() {
  return (await fetch(wasmUrl)).arrayBuffer();
}
