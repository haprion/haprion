(() => {
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
