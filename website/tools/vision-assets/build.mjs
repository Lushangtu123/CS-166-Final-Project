// Rebuild locally after npm ci --ignore-scripts; no package lifecycle scripts run.
import {cp, mkdir, readdir, readFile, writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root = path.dirname(fileURLToPath(import.meta.url));
const output = path.resolve(root, '../../static/vendor/vision');
await mkdir(output, {recursive: true});
async function copy(source, dest) {
  const target = path.join(output, dest);
  await mkdir(path.dirname(target), {recursive: true});
  await cp(path.join(root, 'node_modules', source), target, {recursive: true});
}
for (const name of ['tesseract.esm.min.js', 'worker.min.js', 'worker.min.js.LICENSE.txt', 'tesseract.min.js.LICENSE.txt'])
  await copy('tesseract.js/dist/' + name, name);
await copy('tesseract.js/LICENSE.md', 'licenses/tesseract-js.txt');
for (const variant of ['lstm', 'simd-lstm']) {
  for (const extension of ['wasm.js', 'wasm'])
    await copy(`tesseract.js-core/tesseract-core-${variant}.${extension}`, `core/tesseract-core-${variant}.${extension}`);
}
await copy('tesseract.js-core/LICENSE', 'licenses/tesseract-core.txt');
await copy('jsqr/dist/jsQR.js', 'jsQR.js');
await copy('jsqr/LICENSE', 'licenses/jsqr.txt');
await copy('postal-mime/src', 'postal-mime');
await copy('postal-mime/LICENSE.txt', 'licenses/postal-mime.txt');
await writeFile(path.join(output, 'postal-mime/package.json'), '{"type":"module"}\n');
for (const lang of ['eng', 'chi_sim']) {
  await copy(`@tesseract.js-data/${lang}/4.0.0_best_int/${lang}.traineddata.gz`, `lang/${lang}.traineddata.gz`);
  await copy(`@tesseract.js-data/${lang}/package.json`, `licenses/${lang}-package.json`);
}
await cp(path.join(root, 'tessdata-LICENSE.txt'), path.join(output, 'licenses/tessdata.txt'));
const files = {};
async function walk(dir) {
  for (const entry of await readdir(dir, {withFileTypes: true})) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) await walk(file);
    else if (entry.name !== 'manifest.json') {
      const bytes = await readFile(file);
      files[path.relative(output, file)] = {bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex')};
    }
  }
}
await walk(output);
await writeFile(path.join(output, 'manifest.json'), JSON.stringify({files}, null, 2) + '\n');
console.log(`Prepared ${Object.keys(files).length} self-hosted assets (${Object.values(files).reduce((n, f) => n + f.bytes, 0)} bytes).`);
