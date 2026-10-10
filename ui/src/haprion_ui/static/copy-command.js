(() => {
  // A copy button for every command box, on the receiver pages and the node
  // restore page. The command is the box's text, so what is copied is what is
  // shown - including a name typed into the form a moment ago. The clipboard
  // API needs a secure context, which the interface always is; where it still
  // refuses, the button says so instead of pretending.
  //
  // A box marked `data-copy-beside` gets a full-height button with a word on
  // it beside the box instead of the small one inside it: there the copy is the
  // step (the restore's one line to paste), and a muted corner icon was easy
  // to miss.
  const COPY = '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"></rect><path d="M5 15V6a2 2 0 0 1 2-2h9"></path></svg>';
  const DONE = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m5 12 5 5L20 7"></path></svg>';
  //
  // Wired on load and again after live.js has swapped in the page's content,
  // which arrives without the buttons this adds. A box that has one is left.
  //
  const wire = () => document.querySelectorAll(".receiver-command").forEach((box) => {
    if (box.dataset.copyWired) return;
    box.dataset.copyWired = "1";
    const beside = "copyBeside" in box.dataset;
    const idle = beside ? `${COPY}<span>Copy</span>` : COPY;
    const done = beside ? `${DONE}<span>Copied</span>` : DONE;
    const button = document.createElement("button");
    button.type = "button";
    button.className = beside ? "secondary-button copy-button-beside" : "copy-button";
    button.title = "Copy to clipboard";
    button.setAttribute("aria-label", "Copy to clipboard");
    button.innerHTML = idle;
    button.addEventListener("click", async () => {
      const text = (box.querySelector("code") || box).textContent;
      try {
        await navigator.clipboard.writeText(text);
        button.innerHTML = done;
        button.classList.add("copied");
      } catch {
        button.title = "Copying was refused by the browser";
        button.classList.add("refused");
      }
      window.setTimeout(() => {
        button.innerHTML = idle;
        button.classList.remove("copied", "refused");
      }, 1500);
    });
    if (beside) {
      box.after(button);
    } else {
      box.appendChild(button);
    }
  });
  wire();
  document.addEventListener("haprion:redrawn", wire);
})();
