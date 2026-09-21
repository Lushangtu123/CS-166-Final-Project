import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {checkImage, dataImages, decodeQRs} from './vision-core.mjs';
const require = createRequire(import.meta.url);
const jsQR = require('./vendor/vision/jsQR.js');
const matrices = JSON.parse(readFileSync(new URL('../tests/fixtures/vision/qr-matrices.json', import.meta.url)));
function qrPixels(items) {
  const width = items.length * 500, height = 500;
  const data = new Uint8ClampedArray(width * height * 4).fill(255);
  items.forEach((item,n) => item.matrix.forEach((row,y) => row.forEach((on,x) => {
    if (on) for (let dy=0;dy<10;dy++) for(let dx=0;dx<10;dx++) {
      const offset = ((50+y*10+dy)*width+n*500+50+x*10+dx)*4;
      data[offset]=data[offset+1]=data[offset+2]=0;
    }
  })));
  return {width,height,data};
}
test('real QR decoder reads a synthetic phishing URL without modifying input', () => {
  const image=qrPixels([matrices[1]]), before=image.data.slice();
  assert.deepEqual(decodeQRs(image,jsQR).values,[matrices[1].text]);
  assert.deepEqual(image.data,before);
});
test('two separate QR codes both contribute their exact payloads', () => {
  assert.deepEqual(new Set(decodeQRs(qrPixels(matrices),jsQR).values),new Set(matrices.map(m=>m.text)));
});
test('damaged, oversized dimension and non-image input are rejected before bitmap decode', () => {
  assert.throws(()=>checkImage(new ArrayBuffer(0)),/nonempty/);
  assert.throws(()=>checkImage(new TextEncoder().encode('<svg onload="bad()"/>').buffer),/Unsupported/);
  const png = new Uint8Array(24), view=new DataView(png.buffer);
  png.set([137,80,78,71],0); png.set([73,72,68,82],12);view.setUint32(16,100000);view.setUint32(20,100000);
  assert.throws(()=>checkImage(png.buffer),/megapixels/);
});
test('data images are extracted as bytes and remote URLs remain warnings only', () => {
  const result=dataImages('<img src="data:image/png;base64,aGVsbG8="><img src="https://example.com/track"><script>bad()</script>');
  assert.equal(new TextDecoder().decode(result.images[0].buffer),'hello');
  assert.equal(result.images.length,1);
  assert.match(result.warnings.join(' '),/Remote images/);
});

const {collectEmail} = await import('./vision-email.mjs');
test('real MIME parser extracts inline and attached images as original bytes', async () => {
  const raw=readFileSync(new URL('../tests/fixtures/vision/synthetic-images.eml',import.meta.url));
  const images=[],warnings=[];
  await collectEmail(raw,images,warnings);
  assert.equal(images.length,2);
  assert.equal(images[0].name,'payment-qr.png');
  assert.deepEqual(Buffer.from(images[0].buffer),readFileSync(new URL('../tests/fixtures/vision/synthetic-qr.png',import.meta.url)));
  assert.equal(images[1].source,'mime');
  assert.equal(warnings.length,0);
});
test('MIME extraction caps image count and surfaces the uninspected remainder',async()=>{
  const raw=['MIME-Version: 1.0','Content-Type: multipart/mixed; boundary="X"','','body'];
  for(let n=0;n<6;n++) raw.push('--X','Content-Type: image/png','Content-Transfer-Encoding: base64','', 'aGVsbG8=');
  raw.push('--X--','');
  const images=[],warnings=[];
  await collectEmail(raw.join('\r\n'),images,warnings);
  assert.equal(images.length,4);assert.match(warnings.join(' '),/four-image limit/);
});
