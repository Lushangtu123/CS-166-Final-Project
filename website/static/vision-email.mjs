import PostalMime from './vendor/vision/postal-mime/postal-mime.js';
import {LIMITS, dataImages} from './vision-core.mjs';

export async function collectEmail(buffer, images, warnings, depth = 0) {
  const mail = await PostalMime.parse(buffer, {maxNestingDepth: 20, maxHeadersSize: 32768, maxRfc822NestingDepth: 2, forceRfc822Attachments: true});
  const inline = dataImages(mail.html || '');
  images.push(...inline.images); warnings.push(...inline.warnings);
  for (const item of mail.attachments || []) {
    if (images.length >= LIMITS.images) { warnings.push('Image extraction reached the four-image limit; remaining attachments were not inspected visually.'); break; }
    const content = item.content instanceof ArrayBuffer ? item.content : new Uint8Array(item.content).buffer;
    if (/^image\/(png|jpeg|webp)$/i.test(item.mimeType)) images.push({buffer: content, name: (item.filename || 'inline-image').slice(0, 160), source: 'mime'});
    else if (/^image\//i.test(item.mimeType)) warnings.push('Unsupported image attachments were not inspected.');
    else if (/^message\/(rfc822|global)$/i.test(item.mimeType)) {
      if (depth >= 2) warnings.push('Nested message images exceeded the visual nesting limit.');
      else await collectEmail(content, images, warnings, depth + 1);
    }
  }
}
