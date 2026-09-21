// Pure helpers shared by the worker and tests. No DOM parsing or URL fetching.
export const LIMITS = Object.freeze({bytes: 2 * 1024 * 1024, images: 4, pixels: 8000000, side: 4096, qr: 8});
export function imageInfo(buffer) {
  const b = new Uint8Array(buffer), v = new DataView(buffer);
  const ascii = (i, n) => String.fromCharCode(...b.slice(i, i + n));
  if (b.length >= 24 && ascii(1, 3) === 'PNG' && b[0] === 137 && ascii(12, 4) === 'IHDR')
    return {mime: 'image/png', width: v.getUint32(16), height: v.getUint32(20)};
  if (b.length >= 12 && ascii(0, 4) === 'RIFF' && ascii(8, 4) === 'WEBP') {
    for (let i = 12; i + 8 <= b.length;) {
      const tag = ascii(i, 4), size = v.getUint32(i + 4, true), p = i + 8;
      if (p + size > b.length) break;
      const u24 = n => b[n] | b[n + 1] << 8 | b[n + 2] << 16;
      if (tag === 'VP8X' && size >= 10) return {mime: 'image/webp', width: u24(p + 4) + 1, height: u24(p + 7) + 1, animated: Boolean(b[p] & 2)};
      if (tag === 'VP8 ' && size >= 10) return {mime: 'image/webp', width: v.getUint16(p + 6, true) & 0x3fff, height: v.getUint16(p + 8, true) & 0x3fff};
      if (tag === 'VP8L' && size >= 5 && b[p] === 47) return {mime: 'image/webp', width: 1 + (b[p + 1] | (b[p + 2] & 63) << 8), height: 1 + (b[p + 2] >> 6 | b[p + 3] << 2 | (b[p + 4] & 15) << 10)};
      i = p + size + (size & 1);
    }
  }
  if (b.length >= 4 && b[0] === 255 && b[1] === 216) {
    for (let i = 2; i + 3 < b.length;) {
      if (b[i++] !== 255) break;
      while (b[i] === 255) i++;
      const marker = b[i++];
      if (marker === 217 || marker === 218) break;
      if (marker === 1 || marker >= 208 && marker <= 215) continue;
      if (i + 2 > b.length) break;
      const size = v.getUint16(i);
      if (size < 2 || i + size > b.length) break;
      if ([192, 193, 194, 195, 197, 198, 199, 201, 202, 203, 205, 206, 207].includes(marker) && size >= 8)
        return {mime: 'image/jpeg', height: v.getUint16(i + 3), width: v.getUint16(i + 5)};
      i += size;
    }
  }
  throw new Error('Unsupported or damaged image. Use PNG, JPEG or WebP.');
}
export function checkImage(buffer) {
  if (!buffer.byteLength || buffer.byteLength > LIMITS.bytes) throw new Error('Image must be nonempty and at most 2 MiB.');
  const info = imageInfo(buffer);
  if (!info.width || !info.height || info.width > LIMITS.side || info.height > LIMITS.side || info.width * info.height > LIMITS.pixels)
    throw new Error('Image exceeds 4,096 pixels per side or 8 megapixels.');
  if (info.animated) throw new Error('Animated WebP is not supported; export a still image.');
  return info;
}
export function decodeQRs(image, decode) {
  const {width, height} = image, data = new Uint8ClampedArray(image.data), values = [], warnings = [];
  // jsQR may confuse finder patterns when several codes occupy one image.
  // Overlapping quadrants supply a bounded second pass without fetching targets.
  const regions = [{x: 0, y: 0, w: width, h: height}];
  const rw = Math.ceil(width * .6), rh = Math.ceil(height * .6);
  for (const y of [0, height - rh]) for (const x of [0, width - rw]) regions.push({x, y, w: rw, h: rh});
  let found = 0;
  for (const region of regions) {
    while (found < LIMITS.qr) {
      const pixels = new Uint8ClampedArray(region.w * region.h * 4);
      for (let y = 0; y < region.h; y++) pixels.set(data.subarray(((region.y + y) * width + region.x) * 4, ((region.y + y) * width + region.x + region.w) * 4), y * region.w * 4);
      const qr = decode(pixels, region.w, region.h, {inversionAttempts: 'attemptBoth'});
      if (!qr) break;
      found++;
      if (qr.data.length > 2048) warnings.push('QR payload exceeded 2,048 characters and was truncated.');
      if (!values.includes(qr.data.slice(0, 2048))) values.push(qr.data.slice(0, 2048));
      const points = [qr.location.topLeftCorner, qr.location.topRightCorner, qr.location.bottomLeftCorner, qr.location.bottomRightCorner];
      const left = Math.max(0, region.x + Math.floor(Math.min(...points.map(p => p.x))) - 2);
      const right = Math.min(width, region.x + Math.ceil(Math.max(...points.map(p => p.x))) + 2);
      const top = Math.max(0, region.y + Math.floor(Math.min(...points.map(p => p.y))) - 2);
      const bottom = Math.min(height, region.y + Math.ceil(Math.max(...points.map(p => p.y))) + 2);
      for (let y = top; y < bottom; y++) for (let x = left; x < right; x++) data.fill(255, (y * width + x) * 4, (y * width + x) * 4 + 4);
    }
    if (found === LIMITS.qr) { warnings.push('QR scan reached the eight-code limit; additional codes may be uninspected.'); break; }
  }
  return {values, warnings: [...new Set(warnings)]};
}
export function dataImages(html) {
  const images = [], warnings = [];
  // Scan strings only. Email HTML is never inserted into a document or fetched.
  for (const match of html.matchAll(/data:image\/(png|jpeg|webp);base64,([a-z0-9+/=]+)/gi)) {
    if (images.length >= LIMITS.images) { warnings.push('Additional inline images exceeded the four-image limit.'); break; }
    try {
      const text = atob(match[2]);
      if (text.length > LIMITS.bytes) throw new Error();
      images.push({name: `inline-image-${images.length + 1}`, source: 'data-uri', buffer: Uint8Array.from(text, c => c.charCodeAt(0)).buffer});
    } catch { warnings.push('An inline image could not be decoded within the size limit.'); }
  }
  if (/(?:src|srcset|background|url\s*\()[^<>]{0,40}(?:https?:)?\/\//i.test(html)) warnings.push('Remote images were not downloaded or inspected.');
  if (/data:image\/(?!png[;,]|jpeg[;,]|webp[;,])/i.test(html)) warnings.push('Unsupported inline image formats were not inspected.');
  return {images, warnings};
}
