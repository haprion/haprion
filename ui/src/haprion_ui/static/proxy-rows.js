(() => {
  // The whole row opens the object, not only its name (2026-09-25).
  // One listener on the document rather than one per row: the rows are
  // replaced in place while something is on its way (waiting.js), and a
  // listener on the old ones would leave the new ones dead.
  //
  // The name stays a real link, so a keyboard, a middle click and "open in a
  // new tab" keep working. Anywhere else on the row follows the same address,
  // except over a link or control, which already means something, or while
  // somebody is selecting text with the pointer.
  document.addEventListener("click", (event) => {
    // Settings -> Users uses the same rows (2026-09-27), and so does the
    // search page (B221), and Events -> Audit (26-10-11).
    const row = event.target.closest(
      ".proxy-table tr[data-href], .users-table tr[data-href], .search-table tr[data-href], .audit-table tr[data-href]",
    );
    if (!row || event.button !== 0) return;
    if (event.target.closest("a, button, input, select, textarea, summary, label")) return;
    if (String(window.getSelection() || "")) return;
    if (event.ctrlKey || event.metaKey || event.shiftKey) {
      window.open(row.dataset.href, "_blank", "noopener");
      return;
    }
    window.location.assign(row.dataset.href);
  });
})();
