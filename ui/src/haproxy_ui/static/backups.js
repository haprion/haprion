(() => {
  //
  // The schedule form carries fields for all three frequencies, because the
  // server refuses nothing it did not ask for and ignores what the chosen
  // frequency does not use. What this does is hide the two that do not apply,
  // so a daily schedule is not offered a weekday row it would not read.
  // Without it the form is complete and merely longer.
  //
  const wire = (form) => {
    const frequency = form.querySelector("[data-schedule-frequency]");
    if (!frequency) return;
    const parts = Array.from(form.querySelectorAll("[data-schedule-when]"));
    const show = () => {
      parts.forEach((part) => {
        part.hidden = part.dataset.scheduleWhen !== frequency.value;
      });
    };
    frequency.addEventListener("change", show);
    show();
  };

  window.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("[data-schedule-form]").forEach(wire);
  });
})();
