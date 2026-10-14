(() => {
  //
  // Wired on load and again after live.js has swapped in the page's content
  // while a registration runs; the swapped-in rows and form are new elements.
  //
  const wire = () => {
    // The fetch commands under a row: shown on request, one row at a time.
    // Opening another closes the one that was open; the commands are long,
    // and two open pushed the rest of the list off the screen (26-10-14).
    const toggles = Array.from(document.querySelectorAll("[data-receiver-commands]"));
    const panel = (button) =>
      document.getElementById(`receiver-commands-${button.dataset.receiverCommands}`);
    toggles.forEach((button) => {
      const target = panel(button);
      if (!target) return;
      button.addEventListener("click", () => {
        const open = target.hidden;
        toggles.forEach((other) => {
          const shown = panel(other);
          if (!shown) return;
          shown.hidden = other === button ? !open : true;
          other.setAttribute("aria-expanded", String(other === button && open));
        });
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
      // A name carried over a redraw names the commands too.
      if (name.value.trim()) name.dispatchEvent(new Event("input"));
    }
  };
  wire();
  document.addEventListener("haprion:redrawn", wire);
})();
