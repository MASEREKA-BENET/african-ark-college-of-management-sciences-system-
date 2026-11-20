import { copyFileSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { build } from 'esbuild';

const root = process.cwd();
const output = path.join(root, 'dist');

rmSync(output, { recursive: true, force: true });
mkdirSync(output, { recursive: true });
copyFileSync(path.join(root, 'project.html'), path.join(output, 'index.html'));
copyFileSync(path.join(root, 'ark logo.JPG'), path.join(output, 'ark logo.JPG'));
await build({
  entryPoints: [path.join(root, 'src', 'neon-auth-client.js')],
  bundle: true,
  minify: true,
  format: 'iife',
  platform: 'browser',
  target: ['es2020'],
  outfile: path.join(output, 'neon-auth-client.js'),
});
