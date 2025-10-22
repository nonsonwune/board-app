import esbuild from 'esbuild';
import polyfill from '@esbuild-plugins/node-modules-polyfill';
import path from 'node:path';
import url from 'node:url';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));

await esbuild.build({
  entryPoints: [path.resolve(__dirname, 'src/index.ts')],
  bundle: true,
  format: 'esm',
  outdir: path.resolve(__dirname, 'dist'),
  platform: 'browser',
  target: 'es2022',
  sourcemap: true,
  plugins: [polyfill.NodeModulesPolyfillPlugin()],
  external: ['node:crypto'],
  alias: {
    '@board-app/shared': path.resolve(__dirname, '..', 'packages', 'shared', 'src')
  },
  loader: {
    '.sql': 'text'
  }
});
