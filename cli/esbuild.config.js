import { build } from 'esbuild';

await build({
  entryPoints: ['src/cli.js'],
  bundle: true,
  platform: 'node',
  target: 'node24',
  outfile: 'dist/wormhole.js',
  format: 'esm',
  // Keep node builtins and native/quiche packages external — they cannot be bundled.
  external: [
    'node:*',
    '@fails-components/webtransport',
    '@fails-components/webtransport-transport-http3-quiche',
  ],
  minify: true,
  banner: { js: '#!/usr/bin/env node' },
});

console.log('Bundle written to dist/wormhole.js');
