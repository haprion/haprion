(() => {
  //
  // The advanced config dialog (Fas 17, B223). Modal only, by choice: the
  // button opens the dialog the page already carries, and Check and Save post
  // its form and draw the answer inside it. A save that went through stays in
  // the dialog with every line's fate, so a line that stopped counting is seen
  // (review F3); closing it then loads the address the answer names, so the
  // page shows the new draft.
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
    let saved = "";
    dialog.querySelector("[data-advanced-close]").addEventListener("click", () => dialog.close());
    dialog.addEventListener("close", () => {
      if (saved) window.location.assign(saved);
    });
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
        //
        // The attribute, not `form.action`: the buttons are named `action`, and
        // a form's named controls shadow its properties - `form.action` is
        // then the buttons, and the post went to "[object RadioNodeList]".
        //
        const response = await fetch(form.getAttribute("action"), {
          method: "POST",
          body,
          credentials: "same-origin",
        });
        if (!response.ok) throw new Error(String(response.status));
        const page = new DOMParser().parseFromString(await response.text(), "text/html");
        const answer = page.querySelector("[data-advanced-answer-body]");
        if (!answer) throw new Error("no answer");
        holder.replaceChildren(document.importNode(answer, true));
        //
        // The draft has a new revision now; a second Save from this dialog
        // would carry the old one and be refused, so the buttons go with it.
        //
        if (answer.dataset.advancedSaved) {
          saved = answer.dataset.advancedSaved;
          form.querySelectorAll("button[type=submit]").forEach((button) => {
            button.disabled = true;
          });
        }
      } catch {
        waiting.textContent = "No answer from the server. Nothing was saved.";
      }
    });
  };
  window.addEventListener("DOMContentLoaded", wire);
  document.addEventListener("haproxy-ui:redrawn", wire);
})();
