# Self-hosted browser recognition assets

Pinned packages are installed only in this tooling directory. The application
serves the committed assets in `website/static/vendor/vision`; production does
not run npm or download OCR models on the server.

Rebuild (after approval to install/update dependencies):

```sh
cd website/tools/vision-assets
npm ci --ignore-scripts --no-audit --no-fund
node build.mjs
node verify.mjs
```

`package-lock.json` pins npm integrity hashes; `manifest.json` records the
SHA-256 and byte length of each served asset. CI verifies that manifest without
installing npm packages. No upstream source is modified.

## Sources and attribution

- [jsQR](https://github.com/cozmo/jsQR), 1.4.0, Apache-2.0. Its RGBA decoder is
  wrapped with bounded repeated masking and overlapping quadrant scans for
  multiple codes. Decoded strings are never followed as URLs.
- [Tesseract.js](https://github.com/naptha/tesseract.js), 6.0.1, Apache-2.0;
  [Tesseract.js-core](https://github.com/naptha/tesseract.js-core), 6.0.0,
  Apache-2.0. We follow the upstream self-hosting API with local worker/core/lang
  paths, LSTM-only models and `workerBlobURL: false`. Only LSTM and SIMD-LSTM
  engines are shipped. Upstream bundle license notices are retained.
- [postal-mime](https://github.com/postalsys/postal-mime), 3.0.0, MIT-0. The
  unmodified browser ESM source is used with strict parsing depth/header limits.
- [naptha/tessdata](https://github.com/naptha/tessdata), official npm packages
  `@tesseract.js-data/eng` and `@tesseract.js-data/chi_sim`, 1.0.0,
  `4.0.0_best_int` weights. npm package metadata declares MIT; the model repository
  supplies Apache-2.0. Both package attribution metadata and the upstream model
  license are included. `tessdata-LICENSE.txt` was retrieved from the official
  repository's `gh-pages` branch on 2026-09-20.

Asset size is about 19 MB including engines and both language models. Browser
requests for these assets use the application's own origin. Recognition inputs
are not written into Tesseract's language cache (`cacheMethod: none`).
