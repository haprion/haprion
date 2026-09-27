(() => {
  "use strict";

  //
  // A new password is typed twice. The browser holds the form until the two
  // agree, the way it already holds one that is too short, so a slip of the
  // finger is said beside the field instead of by a round trip. The server
  // checks the same thing again; this only saves the trip.
  //
  for (const repeat of document.querySelectorAll('input[name="repeat_password"]')) {
    const form = repeat.form;
    const first = form && form.elements.namedItem("new_password");
    if (!first) continue;
    const judge = () => {
      repeat.setCustomValidity(
        repeat.value && repeat.value !== first.value ? "The two passwords do not match." : "",
      );
    };
    first.addEventListener("input", judge);
    repeat.addEventListener("input", judge);
    form.addEventListener("submit", (event) => {
      judge();
      if (first.value !== repeat.value) {
        repeat.setCustomValidity("The two passwords do not match.");
        repeat.reportValidity();
        event.preventDefault();
      }
    });
  }
})();
