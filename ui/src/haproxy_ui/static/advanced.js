(() => {
  //
  // The advanced config dialog (Fas 17, B223). Modal only, by choice: the
  // button opens the dialog the page already carries, and Check and Save post
  // its form and draw the answer inside it. A save or publish that went
  // through goes where the editor's would, at once (decided 2026-10-01: the
  // dialog behaves as the editor does).
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
        if (answer.dataset.advancedSaved) {
          window.location.assign(answer.dataset.advancedSaved);
          return;
        }
        holder.replaceChildren(document.importNode(answer, true));
      } catch {
        //
        // No answer is not "nothing happened": the server may have saved the
        // draft and queued the publish before the answer was lost (review
        // 2026-10-04, CR-11). The text stays in the dialog either way.
        //
        waiting.textContent =
          "No answer from the server. Check the object and Jobs before trying again.";
      }
    });
  };
  window.addEventListener("DOMContentLoaded", wire);
  document.addEventListener("haproxy-ui:redrawn", wire);
})();
