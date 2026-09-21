# Synthetic recognition controls

All files here were generated for this project; none contains real mail or user data.
Text images use Pillow and local Arial/Songti fonts. QR matrices were generated with
ReportLab's QR encoder and rendered as black/white squares. These generators are
not application dependencies. Domains use the reserved `.example` suffix.

- `synthetic-qr.png`: `https://paypa1.example/login`.
- `synthetic-multiple-qr.png`: that phishing control and `https://example.com/meeting`.
- `synthetic-phishing.png`: English account suspension and password request.
- `synthetic-benign.png`: routine meeting notes.
- `synthetic-chinese.png`: Chinese account suspension and password request.
- `synthetic-images.eml`: email containing the QR and English images.
- `qr-matrices.json`: real QR matrices used by the decoder tests.

Browser validation on 2026-09-20 decoded both QR codes, recognized the English
control at 92% OCR confidence, and created/reloaded an EML case with both image
observations. Chinese text was extracted at 92% confidence, but its URL was
misread and the result remained unknown with a language-coverage warning.
OCR confidence is not a phishing probability or proof that a URL is exact.
These synthetic controls validate integration, not real-world detection accuracy.
