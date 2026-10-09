(() => {
  //
  // The Servers card (B263): a click anywhere on a row ticks its box, as a
  // click anywhere on a listing's row opens it. Delegated from the document,
  // so a row drawn again by waiting.js answers without being wired up again.
  //
  document.addEventListener("click", (event) => {
    if (event.button !== 0 || event.defaultPrevented) return;
    const row = event.target.closest("[data-select-rows] tbody tr");
    if (!row) return;
    //
    // The box and its label already toggle; a link or a button means
    // something else; and a pointer selecting text is not choosing a row.
    //
    if (event.target.closest("a, button, input, select, textarea, label")) return;
    if (String(window.getSelection() || "")) return;
    const box = row.querySelector('input[type="checkbox"]');
    if (box && !box.disabled) box.checked = !box.checked;
  });
})();
