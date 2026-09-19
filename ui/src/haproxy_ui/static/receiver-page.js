(() => {
  // A copy button at the right end of every command box, on both receiver
  // pages. The command is the box's text, so what is copied is what is
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

  // The fetch commands under a row: shown on request, one row at a time is
  // not enforced - two hosts side by side is a legitimate comparison.
  document.querySelectorAll("[data-receiver-commands]").forEach((button) => {
    const target = document.getElementById(`receiver-commands-${button.dataset.receiverCommands}`);
    if (!target) return;
    button.addEventListener("click", () => {
      const open = target.hidden;
      target.hidden = !open;
      button.setAttribute("aria-expanded", String(open));
    });
  });

  // A failed registration's row can be dismissed: it is a verdict, not a
  // receiver, and the jobs page keeps it. Remembered per browser and per
  // job, so a new failure is never hidden by an old dismissal. Storage can
  // be absent or refuse (private windows); the row then simply stays.
  const DISMISSED = "receiver-dismissed-jobs";
  const dismissed = () => {
    try {
      return JSON.parse(window.localStorage.getItem(DISMISSED) || "[]");
    } catch {
      return [];
    }
  };
  document.querySelectorAll("[data-receiver-ghost]").forEach((row) => {
    if (dismissed().includes(row.dataset.receiverGhost)) row.hidden = true;
  });
  document.querySelectorAll("[data-receiver-dismiss]").forEach((button) => {
    button.addEventListener("click", () => {
      const id = button.dataset.receiverDismiss;
      try {
        window.localStorage.setItem(DISMISSED, JSON.stringify([...dismissed(), id].slice(-20)));
      } catch {
        // Nothing to remember it in; hiding it for now is still right.
      }
      const row = button.closest("[data-receiver-ghost]");
      if (row) row.hidden = true;
    });
  });

  const form = document.querySelector("[data-receiver-form]");
  if (!form) return;
  const keyField = form.querySelector("[data-key-field]");
  const allowField = form.querySelector("[data-allow-field]");
  const name = form.querySelector("[data-receiver-name]");
  const commands = Array.from(form.querySelectorAll("[data-key-command]"));
  const originals = commands.map((node) => node.textContent);
  const windowsBlocks = Array.from(form.querySelectorAll('[data-os="windows"]'));

  // The key and the allowlist are the two halves of one choice: an ssh
  // transport has a key, https has an allowlist, never both. And the key
  // steps follow the transport: Windows is shown for the transports a
  // Windows host can use (the radio says which), never for rsync.
  const showFor = (radio) => {
    const https = radio.value === "https";
    if (keyField) keyField.hidden = https;
    if (allowField) allowField.hidden = !https;
    const windows = radio.hasAttribute("data-windows");
    windowsBlocks.forEach((node) => { node.hidden = !windows; });
  };
  form.querySelectorAll("[data-transport-choice]").forEach((radio) => {
    radio.addEventListener("change", () => showFor(radio));
    if (radio.checked) showFor(radio);
  });

  // The key-making command names the receiver, so it can be copied as is.
  if (name) {
    name.addEventListener("input", () => {
      const value = name.value.trim() || "<receiver>";
      commands.forEach((node, index) => {
        node.textContent = originals[index].replace(/<receiver>|(?<=-C )\S+/g, value);
      });
    });
  }
})();
