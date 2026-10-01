(() => {
  //
  // The advanced config dialog (Fas 17, B223). Modal only, by choice: the
  // button opens the dialog the page already carries, and Check and Save post
  // its form and draw the answer inside it. A save that went through follows
  // the address the answer names, so the page shows the new draft.
  //
  const wire = () => {
    const dialog = document.querySelector("[data-advanced-dialog]");
    if (!dialog || dialog.dataset.wired) return;
    dialog.dataset.wired = "1";
    const form = dialog.querySelector("[data-advanced-form]");
    const holder = dialog.querySelector("[data-advanced-answer]");
    document.querySelectorAll("[data-advanced-open]").forEach((button) => {
      button.addEventListener("click", () => dialog.showModal());
    });
    dialog.querySelector("[data-advanced-close]").addEventListener("click", () => dialog.close());
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const body = new FormData(form);
      if (event.submitter && event.submitter.name) body.set(event.submitter.name, event.submitter.value);
      holder.replaceChildren();
      const waiting = document.createElement("p");
      waiting.className = "advanced-waiting";
      waiting.textContent = "Checking…";
      holder.append(waiting);
      try {
        const response = await fetch(form.action, { method: "POST", body, credentials: "same-origin" });
        if (!response.ok) throw new Error(String(response.status));
        const page = new DOMParser().parseFromString(await response.text(), "text/html");
        const answer = page.querySelector("[data-advanced-answer-body]");
        if (!answer) throw new Error("no answer");
        if (answer.dataset.advancedSaved) {
          window.location.assign(answer.dataset.advancedSaved);
          return;
        }
        holder.replaceChildren(document.importNode(answer, true));
      } catch {
        waiting.textContent = "No answer from the server. Nothing was saved.";
      }
    });
  };
  window.addEventListener("DOMContentLoaded", wire);
  document.addEventListener("haproxy-ui:redrawn", wire);
})();
