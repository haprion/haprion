(() => {
  // Proxies belong to a block token only; for the other levels the field is
  // hidden, so what is ticked there cannot be posted by mistake. Without
  // script the field stays, and the server refuses proxies on another level.
  const levels = Array.from(document.querySelectorAll("input[data-level]"));
  const fields = Array.from(document.querySelectorAll("[data-for-level]"));
  const sync = () => {
    const chosen = levels.find((input) => input.checked);
    fields.forEach((field) => {
      const shown = chosen && chosen.value === field.dataset.forLevel;
      field.hidden = !shown;
      field.querySelectorAll("input").forEach((input) => { input.disabled = !shown; });
    });
  };
  levels.forEach((input) => input.addEventListener("change", sync));
  sync();
})();
