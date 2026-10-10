(() => {
  //
  // A button that opens a dialog the page already carries, and the dialog's own
  // Close: `data-open-dialog="<id>"` and `data-close-dialog` (B257, the
  // dashboard's Publish & deploy). Listened for on the document rather than
  // wired to the buttons, because live.js swaps the page's content in place and
  // the buttons it draws are new ones each time.
  //
  document.addEventListener("click", (event) => {
    const opener = event.target.closest("[data-open-dialog]");
    if (opener) {
      const dialog = document.getElementById(opener.dataset.openDialog);
      if (dialog && typeof dialog.showModal === "function" && !dialog.open) {
        dialog.showModal();
        const field = dialog.querySelector("input:not([type=hidden]), textarea");
        if (field) field.focus();
      }
      return;
    }
    const closer = event.target.closest("[data-close-dialog]");
    if (closer) {
      const dialog = closer.closest("dialog");
      if (dialog) dialog.close();
    }
  });
})();
