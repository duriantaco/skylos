import { defineConfig } from "tsdown";

const modern = (options: { entry: string[] }) => ({ ...options, outDir: "build/modern", dts: true });

export default defineConfig([modern({ entry: ["src/index.ts", "src/production.ts"] })]);
