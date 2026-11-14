# fx

Run the evals:

```bash
bun run src/evals/run.ts --sample 10
```

Rebuild the table:

```bash
yarn install
./node_modules/.bin/ts-node --compiler-options '{"esModuleInterop": true}' ./tools/make.ts
```

Some notes mention `node tools/inline.ts` in passing.

The old tools/legacy.ts script was removed. See [the list](tools/linked.ts).

```
cat tools/catted.ts
```

```ts
// node tools/snippet.ts
```
