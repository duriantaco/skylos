export const mainConfig = {
  entry: { app: './lib/app.ts' },
  module: { rules: [{ test: /\.ts$/, exclude: ['./lib/excluded.ts'] }] },
};
