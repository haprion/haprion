(() => {
  //
  // Allow… (B235, mock round 7) in a dialog over the WAF page. The button is a
  // link to the Allow page, which is what it stays without script; with it, the
  // page's form is fetched into a dialog. Allow posts the form from there: a
  // saved exception goes where the page would have gone, and a refusal is
  // answered inside the same dialog. Cancel, Escape and a click outside shut it.
  //
  let dialog = null;
  const shell = () => {
    if (dialog) return dialog;
    dialog = document.createElement("dialog");
    dialog.className = "allow-modal";
    dialog.setAttribute("aria-label", "Allow a finding");
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close();
    });
    document.body.append(dialog);
    return dialog;
  };

  const show = (html, fallback) => {
    const page = new DOMParser().parseFromString(html, "text/html");
    const form = page.querySelector("form.allow-dialog");
    if (!form) {
      window.location.href = fallback;
      return;
    }
    const shown = shell();
    shown.replaceChildren(document.importNode(form, true));
    const cancel = shown.querySelector("[data-allow-cancel]");
    if (cancel) {
      cancel.addEventListener("click", (event) => {
        event.preventDefault();
        shown.close();
      });
    }
    shown.querySelector("form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const target = event.currentTarget;
      try {
        const response = await fetch(target.action, {
          method: "POST",
          // Encoded as the form itself posts, not as multipart.
          body: new URLSearchParams(new FormData(target)),
          credentials: "same-origin",
        });
        if (response.redirected) {
          window.location.href = response.url;
          return;
        }
        show(await response.text(), fallback);
      } catch {
        target.submit();
      }
    });
    if (!shown.open) shown.showModal();
  };

  document.addEventListener("click", async (event) => {
    const link = event.target instanceof Element ? event.target.closest("[data-waf-allow]") : null;
    if (!link || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey) return;
    if (typeof HTMLDialogElement === "undefined") return;
    event.preventDefault();
    try {
      const response = await fetch(link.href, { credentials: "same-origin" });
      if (!response.ok) throw new Error(String(response.status));
      show(await response.text(), link.href);
    } catch {
      window.location.href = link.href;
    }
  });
})();
