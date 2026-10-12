(() => {
  // The whole row opens the object, not only its name (2026-09-25).
  // One listener on the document rather than one per row: the rows are
  // replaced in place while something is on its way (waiting.js), and a
  // listener on the old ones would leave the new ones dead.
  //
  // The name stays a real link, so a keyboard, a middle click and "open in a
  // new tab" keep working. Anywhere else on the row follows the same address,
  // except over a link or control, which already means something, or while
  // somebody is selecting text with the pointer.
  document.addEventListener("click", (event) => {
    // Settings -> Users uses the same rows (2026-09-27), and so does the
    // search page (B221), and Events -> Audit (26-10-11). The other settings
    // rows - Logs & metrics, Nodes, External monitoring - wore the pointer and
    // went nowhere outside their name and button (26-10-12).
    const row = event.target.closest(
      ".proxy-table tr[data-href], .users-table tr[data-href], .search-table tr[data-href], .audit-table tr[data-href], .settings-cluster-table tr[data-href]",
    );
    if (!row || event.button !== 0) return;
    if (event.target.closest("a, button, input, select, textarea, summary, label")) return;
    if (String(window.getSelection() || "")) return;
    if (event.ctrlKey || event.metaKey || event.shiftKey) {
      window.open(row.dataset.href, "_blank", "noopener");
      return;
    }
    if (row.closest(AUDIT)) {
      unfold(row.dataset.href, true).catch(() => window.location.assign(row.dataset.href));
      return;
    }
    window.location.assign(row.dataset.href);
  });

  //
  // An audit row does not leave the page: it unfolds its detail under itself
  // (26-10-11), and a navigation for that threw the reader back to the top of
  // a long record (26-10-12). The same address is fetched and only the table
  // swapped in, as Certificates does for its registry rows; the address still
  // says which row is open, so back closes it again. Anything unexpected - a
  // session that expired into the login form - falls back to the navigation.
  //
  const AUDIT = ".audit-table";
  const unfold = async (href, push) => {
    const answer = await fetch(href, { credentials: "same-origin", headers: { Accept: "text/html" } });
    if (!answer.ok || answer.redirected) throw new Error(String(answer.status));
    const parsed = new DOMParser().parseFromString(await answer.text(), "text/html");
    const fresh = parsed.querySelector(AUDIT);
    const here = document.querySelector(AUDIT);
    if (!fresh || !here) throw new Error("shape");
    here.replaceWith(fresh);
    if (push) history.pushState({ audit: true }, "", href);
  };
  window.addEventListener("popstate", () => {
    if (!document.querySelector(AUDIT)) return;
    unfold(window.location.href, false).catch(() => window.location.reload());
  });
})();
