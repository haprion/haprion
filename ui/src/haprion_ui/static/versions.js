(() => {
  //
  // The version list arrives whole, each row marked with its page, and the
  // server has already hidden every page but the first - the archive list on
  // Node backups works the same way. Without this the ten newest are still
  // there and the older ones are simply not offered.
  //
  const page = (list) => {
    const rows = Array.from(list.querySelectorAll("[data-version-page]"));
    const range = list.querySelector("[data-version-page-range]");
    const newer = list.querySelector("[data-version-page-previous]");
    const older = list.querySelector("[data-version-page-next]");
    const frame = list.querySelector(".table-scroll");
    if (!newer || !older) return;
    const perPage = Number(list.dataset.versionPerPage) || 10;
    const count = Number(list.dataset.versionCount) || rows.length;
    const pages = Math.max(Math.ceil(count / perPage), 1);
    let current = 0;
    const show = () => {
      rows.forEach((row) => {
        row.hidden = Number(row.dataset.versionPage) !== current;
      });
      const first = current * perPage + 1;
      const last = Math.min((current + 1) * perPage, count);
      if (range) range.textContent = `Versions ${first}–${last} of ${count} · page ${current + 1} of ${pages}`;
      newer.disabled = current === 0;
      older.disabled = current >= pages - 1;
    };
    newer.addEventListener("click", () => {
      current = Math.max(current - 1, 0);
      show();
    });
    older.addEventListener("click", () => {
      //
      // The last page is usually shorter. Holding the first page's height keeps
      // the buttons under the pointer instead of the list shrinking beneath it.
      //
      if (current === 0 && frame) frame.style.minHeight = `${frame.offsetHeight}px`;
      current = Math.min(current + 1, pages - 1);
      show();
    });
    show();
  };

  //
  // What one version changed (B220), in a dialog. The button is a link to the
  // version's own page; with script that page is fetched and its section lifted
  // into one dialog shared by every row. Escape and the close button shut it
  // (the browser's own <dialog> behaviour), and so does a click outside it.
  //
  let dialog = null;
  const ensureDialog = () => {
    if (dialog) return dialog;
    dialog = document.createElement("dialog");
    dialog.className = "version-changes-dialog";
    dialog.setAttribute("aria-label", "Changes in this version");
    const close = document.createElement("button");
    close.type = "button";
    close.className = "secondary-button version-changes-close";
    close.textContent = "Close";
    close.addEventListener("click", () => dialog.close());
    const holder = document.createElement("div");
    holder.dataset.versionChangesHolder = "";
    dialog.append(close, holder);
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close();
    });
    document.body.append(dialog);
    return dialog;
  };
  const openChanges = async (link) => {
    const shown = ensureDialog();
    const holder = shown.querySelector("[data-version-changes-holder]");
    holder.replaceChildren();
    const waiting = document.createElement("p");
    waiting.className = "table-note";
    waiting.textContent = "Reading…";
    holder.append(waiting);
    shown.showModal();
    try {
      const response = await fetch(link.href, { credentials: "same-origin" });
      if (!response.ok) throw new Error(String(response.status));
      const page = new DOMParser().parseFromString(await response.text(), "text/html");
      const body = page.querySelector("[data-version-changes-body]");
      if (!body) throw new Error("no changes section");
      holder.replaceChildren(document.importNode(body, true));
    } catch {
      waiting.textContent = "Could not be read. Open the version's own page instead.";
    }
  };
  document.addEventListener("click", (event) => {
    const link = event.target instanceof Element ? event.target.closest("[data-version-changes]") : null;
    if (!link || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey) return;
    if (typeof HTMLDialogElement === "undefined") return;
    event.preventDefault();
    openChanges(link);
  });

  //
  // On load, and again when waiting.js has swapped in the page's content.
  //
  const wireAll = () => document.querySelectorAll("[data-version-list]").forEach(page);
  window.addEventListener("DOMContentLoaded", wireAll);
  document.addEventListener("haprion:redrawn", wireAll);
})();

(() => {
  //
  // Publishing an earlier version asks first (26-10-18): the button sits on
  // every row, and one wrong click published an old version. The form says
  // what to ask; without script it posts as it always did.
  //
  let pending = null;
  document.addEventListener("submit", (event) => {
    const form = event.target.closest("form[data-confirm-version]");
    const dialog = document.getElementById("version-confirm");
    if (!form || !dialog || typeof dialog.showModal !== "function") return;
    if (form.dataset.confirmed === "yes") return;
    event.preventDefault();
    pending = form;
    dialog.querySelector("[data-confirm-title]").textContent = form.dataset.confirmVersion;
    dialog.querySelector("[data-confirm-text]").textContent = form.dataset.confirmDetail;
    dialog.querySelector("[data-confirm-go]").textContent = form.dataset.confirmButton;
    dialog.showModal();
    dialog.querySelector("[data-confirm-cancel]").focus();
  });
  document.addEventListener("click", (event) => {
    const dialog = document.getElementById("version-confirm");
    if (!dialog) return;
    if (event.target.closest("[data-confirm-cancel]")) {
      pending = null;
      dialog.close();
    } else if (event.target.closest("[data-confirm-go]") && pending) {
      const form = pending;
      pending = null;
      dialog.close();
      form.dataset.confirmed = "yes";
      form.requestSubmit();
    }
  });
})();
