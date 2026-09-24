(() => {
  // A copy button at the right end of every command box, on the receiver
  // pages and the node restore page. The command is the box's text, so what is copied is what is
  // shown - including a name typed into the form a moment ago. The
  // clipboard API needs a secure context, which the interface always is;
  // where it still refuses, the button says so instead of pretending.
  const COPY = '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"></rect><path d="M5 15V6a2 2 0 0 1 2-2h9"></path></svg>';
  const DONE = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m5 12 5 5L20 7"></path></svg>';
  document.querySelectorAll(".receiver-command").forEach((box) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "copy-button";
    button.title = "Copy to clipboard";
    button.setAttribute("aria-label", "Copy to clipboard");
    button.innerHTML = COPY;
    button.addEventListener("click", async () => {
      const text = (box.querySelector("code") || box).textContent;
      try {
        await navigator.clipboard.writeText(text);
        button.innerHTML = DONE;
        button.classList.add("copied");
      } catch {
        button.title = "Copying was refused by the browser";
        button.classList.add("refused");
      }
      window.setTimeout(() => {
        button.innerHTML = COPY;
        button.classList.remove("copied", "refused");
      }, 1500);
    });
    box.appendChild(button);
  });
})();
