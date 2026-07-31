// With `build.format: 'file'` (astro.config.mjs), Astro collapses nested
// `index.astro` routes to `<parent-dir>.html` instead of
// `<parent-dir>/index.html` (e.g. src/pages/doc/5.6/index.astro ->
// dist/doc/5.6.html). That breaks the trailing-slash directory URL
// (/doc/5.6/) that GitHub Pages needs to serve such a page, which is also
// the pre-migration canonical URL for these pages (they were literal
// `.../index.html` files in the old Jekyll site). This copies each such
// generated file to also live at `<parent-dir>/index.html`.
//
// Runs after `pagefind --site dist` so Pagefind only indexes the original
// file, not the duplicate.

import { readdir, mkdir, copyFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const pagesDir = path.join(rootDir, 'src', 'pages');
const distDir = path.join(rootDir, 'dist');

async function findNestedIndexDirs(dir, relDir = '') {
  const entries = await readdir(dir, { withFileTypes: true });
  const dirs = [];
  for (const entry of entries) {
    if (entry.isDirectory()) {
      dirs.push(...(await findNestedIndexDirs(path.join(dir, entry.name), path.join(relDir, entry.name))));
    } else if (relDir && entry.name === 'index.astro') {
      dirs.push(relDir);
    }
  }
  return dirs;
}

const nestedIndexDirs = await findNestedIndexDirs(pagesDir);

for (const relDir of nestedIndexDirs) {
  const src = path.join(distDir, `${relDir}.html`);
  const destDir = path.join(distDir, relDir);
  const dest = path.join(destDir, 'index.html');

  try {
    await stat(src);
  } catch {
    console.warn(`duplicate-index-pages: skipping ${relDir} - ${src} not found`);
    continue;
  }

  await mkdir(destDir, { recursive: true });
  await copyFile(src, dest);
  console.log(`duplicate-index-pages: ${path.relative(distDir, src)} -> ${path.relative(distDir, dest)}`);
}
