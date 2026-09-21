/* User-initiated local files only; never fetch dropped URLs or read the clipboard automatically. */
'use strict';
window.PhishGuardFiles = {
  bind({zone, input, enabled = () => true, onError}) {
    if (!zone || !input) return;
    const hasFiles = data => Array.from(data?.types || []).includes('Files') || data?.files?.length > 0 ||
      Array.from(data?.items || []).some(item => item.kind === 'file');
    const clearHighlight = () => { zone.classList.remove('drag-active'); };
    function accept(data) {
      const files = Array.from(data?.files || []);
      if (!files.length) for (const item of Array.from(data?.items || [])) {
        if (item.kind === 'file') { const file = item.getAsFile(); if (file) files.push(file); }
      }
      let error;
      const file = files[0];
      if (files.length !== 1) error = 'Drop or paste one file at a time.';
      else if (!/\.(eml|png|jpe?g|webp)$/i.test(file.name) &&
               !['message/rfc822','image/png','image/jpeg','image/webp'].includes(file.type))
        error = 'Choose a PNG, JPEG, WebP image or an .eml email.';
      else if (!file.size || file.size > 2 * 1024 * 1024) error = 'Choose a nonempty file up to 2 MiB.';
      if (!error) {
        try {
          const transfer = new DataTransfer(); transfer.items.add(file); input.files = transfer.files;
        } catch { error = 'This browser could not attach the file. Use Choose File instead.'; }
      }
      if (error) input.value = '';
      // Both entry points keep their existing cancellation, byte validation and retry behavior.
      input.dispatchEvent(new Event('change', {bubbles:true}));
      if (error) onError(error);
    }
    for (const name of ['dragenter','dragover']) zone.addEventListener(name, event => {
      if (!enabled() || !hasFiles(event.dataTransfer)) return;
      event.preventDefault(); event.dataTransfer.dropEffect = 'copy'; zone.classList.add('drag-active');
    });
    zone.addEventListener('dragleave', event => {
      if (!zone.contains(event.relatedTarget)) clearHighlight();
    });
    zone.addEventListener('drop', event => {
      clearHighlight();
      if (!hasFiles(event.dataTransfer)) return;
      event.preventDefault(); event.stopPropagation();
      if (enabled()) accept(event.dataTransfer);
    });
    zone.addEventListener('paste', event => {
      if (!enabled() || !hasFiles(event.clipboardData)) return;
      event.preventDefault(); accept(event.clipboardData);
    });
    // A missed drop must not replace the page with the local file.
    for (const name of ['dragover','drop']) document.addEventListener(name, event => {
      if (hasFiles(event.dataTransfer)) event.preventDefault();
      if (name === 'drop') clearHighlight();
    });
    window.addEventListener('dragend', clearHighlight);
    window.addEventListener('blur', clearHighlight);
  },
};
