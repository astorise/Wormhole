import { build } from 'esbuild';

await build({
  entryPoints: ['src/cli.js'],
  bundle: true,
  platform: 'node',
  target: 'node20',
  outfile: 'dist/wormhole.js',
  format: 'esm',
  external: ['node:*'],
  minify: true,
  banner: { js: '#!/usr/bin/env node' },
});

console.log('Bundle written to dist/wormhole.js');
