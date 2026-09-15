(() => {
  "use strict";

  //
  // The confirm button is greyed until a target is ticked, the way the
  // registry's delete button is until a certificate is. The server refuses
  // an empty choice as well; this only saves the round trip.
  //
  const wire = () => {
    const picks = Array.from(document.querySelectorAll("[data-target-pick]"));
    const submit = document.querySelector("[data-target-submit]");
    if (!submit || !picks.length) return;
    const update = () => {
      submit.disabled = !picks.some((pick) => pick.checked);
    };
    picks.forEach((pick) => pick.addEventListener("change", update));
    update();
  };

  window.addEventListener("DOMContentLoaded", wire);
})();
