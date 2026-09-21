# QR and image text recognition

## Accepted scope

Browser-side recognition on the public analyzer and authenticated case workbench.
Users select a PNG/JPEG/WebP image or an original EML. EML image attachments are
extracted locally. QR payloads and English/Simplified Chinese OCR text become
explicitly attributed, client-extracted evidence for server-side risk analysis.
No remote image or decoded link is fetched. No third-party OCR service is used.

Use self-hosted, pinned jsQR (Apache-2.0), Tesseract.js/core (Apache-2.0),
postal-mime (MIT-0), and official Tesseract language data. Reference upstream
documentation and retain licenses. RapidOCR/ZXing-C++ were considered; browser
recognition avoids adding native OCR libraries to the existing Vercel function.

## Boundaries

Recognition is an assistive extraction step, not proof of message safety. The
server validates bounded evidence, recomputes risk, never accepts a client
verdict, and never lets benign OCR lower risk from original email evidence.
Original attachment coverage warnings remain: OCR/QR does not scan malware,
logos, image meaning, every animation frame, or all text. API-only EML requests
do not perform OCR. Unsupported, failed, timed-out, or capped scans stay explicit.

Images are processed in a same-origin worker with byte/pixel/count/time limits;
no HTML from EML is rendered. Remote images remain uninspected. Local HTML data
images are extracted without navigating or rendering the document. Browser
results are displayed as plain text, never auto-linked or executed. File changes,
clear, sign-out, and cancelled work invalidate late results and terminate workers.

Visual submissions use dedicated bounded API routes, preserve original EML bytes
as base64 when present, and keep the existing small limits for other endpoints.
Cases retain extracted text, QR payloads, image digest, status, and extractor
version; original image bytes are not retained. Auth, optimistic locking, and
idempotency remain unchanged. Independent original-message and visual findings
are merged conservatively, with provenance visible in both result views.

## Implementation and acceptance

1. Pin/install assets with lifecycle scripts disabled; copy only browser assets,
   language data and licenses, record SHA-256 manifest and verification script.
2. Implement bounded visual evidence API and case integration; test positive QR
   and OCR controls, benign/blank evidence, malformed payloads, no downgrade,
   auth/idempotency, byte limits, and raw-byte preservation.
3. Implement shared cancellable recognition worker and two UI integrations;
   test extraction, bounds, multiple QR codes, failed OCR, stale work and safe rendering.
4. Test real QR and OCR fixtures in the browser, Python and frontend suites,
   Vercel runtime smoke, syntax, and diff. Report local verification separately
   from production deployment; publishing requires separate authorization.
