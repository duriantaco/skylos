// './lib/mentioned.ts' was the old renderer
const config = {
  packagerConfig: {
    extraResource: ['lib/resource-en.js'],
  },
  plugins: [
    {
      renderer: {
        entryPoints: [{ html: './lib/index.html', js: './lib/renderer.ts', preload: { js: './lib/preload.ts' } }],
      },
    },
  ],
};

export default config;
