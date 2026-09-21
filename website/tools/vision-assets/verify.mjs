import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const root = new URL('../../static/vendor/vision/', import.meta.url);
const manifest = JSON.parse(await readFile(new URL('manifest.json', root)));
for (const [file, expected] of Object.entries(manifest.files)) {
  const bytes = await readFile(new URL(file, root));
  if (bytes.length !== expected.bytes || createHash('sha256').update(bytes).digest('hex') !== expected.sha256)
    throw new Error(`Recognition asset does not match its pinned manifest: ${file}`);
}
console.log(`Verified ${Object.keys(manifest.files).length} recognition assets.`);
