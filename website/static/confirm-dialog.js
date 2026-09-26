/* Themed replacement for window.confirm(). Resolves true only for the confirm button. */
'use strict';
(() => {
  let sequence = 0;
  window.PhishGuardConfirm = function confirmDialog(message, {confirmLabel = 'Continue', cancelLabel = 'Cancel'} = {}) {
    if (typeof HTMLDialogElement !== 'function' || typeof document.createElement('dialog').showModal !== 'function') {
      return Promise.resolve(window.confirm(message));
    }
    return new Promise(resolve => {
      const id = 'pg-confirm-message-' + (++sequence);
      const dialog = document.createElement('dialog');
      dialog.className = 'pg-confirm';
      dialog.setAttribute('aria-describedby', id);
      const form = document.createElement('form');
      form.method = 'dialog';
      const text = document.createElement('p');
      text.className = 'pg-confirm-message';
      text.id = id;
      text.textContent = message;
      const actions = document.createElement('div');
      actions.className = 'pg-confirm-actions';
      const cancel = document.createElement('button');
      cancel.value = 'cancel';
      cancel.className = 'btn-ghost pg-confirm-cancel';
      cancel.textContent = cancelLabel;
      const ok = document.createElement('button');
      ok.value = 'confirm';
      ok.className = 'btn btn-primary primary pg-confirm-ok';
      ok.textContent = confirmLabel;
      actions.append(cancel, ok);
      form.append(text, actions);
      dialog.append(form);
      dialog.addEventListener('close', () => {
        resolve(dialog.returnValue === 'confirm');
        // Leave time for the closing transition before removing the node.
        setTimeout(() => dialog.remove(), 320);
      }, {once: true});
      document.body.append(dialog);
      dialog.showModal();
      // Default focus stays on the non-destructive choice.
      cancel.focus();
    });
  };
})();
