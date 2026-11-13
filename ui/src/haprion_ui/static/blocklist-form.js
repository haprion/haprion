(() => {
  // The username goes with Basic and the secret's field with its kind; what
  // is hidden is disabled too, so it is not posted. Test asks the server
  // without leaving the page, so a typed password stays in its field. Without
  // script the fields are those the page was drawn with, and Test draws the
  // form again with its answer.
  const form = document.querySelector("form[data-blocklist-form]");
  if (!form) return;
  const auth = form.querySelector("select[data-blocklist-auth]");
  const sync = () => {
    form.querySelectorAll("[data-for-auth]").forEach((field) => {
      const shown = auth.value === field.dataset.forAuth;
      field.hidden = !shown;
      field.querySelectorAll("input").forEach((input) => { input.disabled = !shown; });
    });
  };
  auth.addEventListener("change", sync);
  sync();

  const test = form.querySelector("button[data-blocklist-test]");
  const answer = form.querySelector("[data-test-answer]");
  test.addEventListener("click", async (event) => {
    event.preventDefault();
    const body = new FormData(form);
    body.set("action", "test");
    test.disabled = true;
    answer.hidden = false;
    answer.textContent = "Fetching…";
    try {
      const response = await fetch(form.action, {
        method: "POST",
        body,
        headers: { Accept: "application/json" },
        credentials: "same-origin",
      });
      const said = await response.json();
      if (said.page) {
        form.requestSubmit(test);
        return;
      }
      const dot = document.createElement("span");
      dot.className = `status-dot status-${said.tone === "healthy" ? "healthy" : "critical"}`;
      dot.setAttribute("aria-hidden", "true");
      answer.replaceChildren(dot, document.createTextNode(String(said.answer)));
    } catch (error) {
      answer.textContent = "The test got no answer. Try again.";
    } finally {
      test.disabled = false;
    }
  });
})();
