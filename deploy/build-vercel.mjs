import { copyFileSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const output = path.join(root, 'dist');

rmSync(output, { recursive: true, force: true });
mkdirSync(output, { recursive: true });
copyFileSync(path.join(root, 'project.html'), path.join(output, 'index.html'));
copyFileSync(path.join(root, 'ark logo.JPG'), path.join(output, 'ark logo.JPG'));
