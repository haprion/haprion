(() => {
  //
  // The certificate page's two views, and the detail row under a registry
  // entry, without reloading the page around them.
  //
  // Which view is open and which entry is unfolded live in the address - that
  // is what makes a certificate something you can paste to somebody - so every
  // click is a navigation, and a navigation redraws the whole page and throws
  // the reader back to the top of it. Traffic solved the same thing the same
  // way, and this is that solution again: fetch the very same address, swap in
  // the region the server rendered for it, and let the server keep doing all
  // the reading. Nothing here knows what a certificate is.
  //
  // Without this script the links are plain links and behave as they always
  // did, which is the reason they are links in the first place.
  //
  const REGION = "[data-certificates-region]";

  //
  // A certificate job changes this page without a click. The old meta refresh
  // kept the address the document first loaded at, so switching views in place
  // and then reaching its timer jumped back to that first view. Redraw the
  // browser's current address instead (live.js), in place rather than as a
  // reload; history and the visible view now agree.
  //
  let refreshTimer = null;
  const wireRefresh = () => {
    if (refreshTimer !== null) window.clearTimeout(refreshTimer);
    refreshTimer = null;
    const region = document.querySelector(REGION);
    if (region && region.dataset.refresh === "true") {
      refreshTimer = window.setTimeout(() => {
        if (window.haproxyUi) window.haproxyUi.redraw();
        else window.location.reload();
      }, 3000);
    }
  };

  //
  // The registry's delete button is greyed until something is ticked, and
  // says how many. Wired after every swap as well as on load, because the
  // region the boxes live in is replaced whole by a navigation.
  //
  const wireDeletion = () => {
    const form = document.querySelector("[data-delete-form]");
    if (!form) return;
    const picks = Array.from(form.querySelectorAll("[data-delete-pick]"));
    const submits = Array.from(form.querySelectorAll("[data-delete-submit]"));
    const singles = Array.from(form.querySelectorAll("[data-single-submit]"));
    const exports = Array.from(form.querySelectorAll("[data-export-submit]"));
    const waiting = Array.from(form.querySelectorAll("[data-pending-submit]"));
    const count = form.querySelector("[data-delete-count]");
    const update = () => {
      const chosen = picks.filter((pick) => pick.checked).length;
      submits.forEach((submit) => { submit.disabled = chosen === 0; });
      singles.forEach((submit) => { submit.disabled = chosen !== 1; });
      const exportable = picks.filter((pick) => pick.checked && pick.hasAttribute("data-exportable")).length;
      exports.forEach((submit) => { submit.disabled = chosen !== 1 || exportable !== 1; });
      const pending = picks.filter((pick) => pick.checked && pick.hasAttribute("data-pending")).length;
      waiting.forEach((submit) => { submit.disabled = chosen !== 1 || pending !== 1; });
      if (count) count.textContent = chosen === 0 ? "Nothing selected" : `${chosen} selected`;
    };
    picks.forEach((pick) => pick.addEventListener("change", update));
    update();
  };

  const swap = async (href, push) => {
    const answer = await fetch(href, { credentials: "same-origin" });
    if (!answer.ok) throw new Error(String(answer.status));
    const parsed = new DOMParser().parseFromString(await answer.text(), "text/html");
    const fresh = parsed.querySelector(REGION);
    const here = document.querySelector(REGION);
    //
    // Refused rather than patched up. A page without the region is a different
    // page - a session that expired into a login form - and half-replacing it
    // would leave the reader looking at two answers at once.
    //
    if (!fresh || !here) throw new Error("shape");
    //
    // What the reader ticked stays ticked (review 26-10-24, 04-11): opening a
    // row's detail to read it before deleting took every tick away.
    //
    const ticked = new Set(
      Array.from(here.querySelectorAll("[data-delete-pick]:checked"), (pick) => pick.value),
    );
    fresh.querySelectorAll("[data-delete-pick]").forEach((pick) => {
      if (ticked.has(pick.value)) pick.checked = true;
    });
    here.replaceWith(fresh);
    wireDeletion();
    wireRefresh();
    const freshRanges = parsed.querySelector(".page-ranges-sticky");
    const hereRanges = document.querySelector(".page-ranges-sticky");
    if (freshRanges && hereRanges) hereRanges.replaceWith(freshRanges);
    if (push) history.pushState({ certificates: true }, "", href);
  };

  const follow = (href) => {
    swap(href, true).catch(() => {
      //
      // Anything unexpected - offline, a redirect to a login page, a shape
      // that no longer matches - falls back to the navigation this replaced.
      //
      window.location.href = href;
    });
  };

  document.addEventListener("click", (event) => {
    if (event.button !== 0 || event.defaultPrevented) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const pick = event.target.closest(".certificate-views a, .registry-table .proxy-link");
    if (pick) {
      event.preventDefault();
      follow(pick.getAttribute("href"));
      return;
    }
    //
    // The rest of the row opens the detail too - anywhere on it, not only
    // the name. Never over a selection somebody is making with the pointer,
    // and never over a link or control, which already mean something.
    //
    const row = event.target.closest(".registry-row");
    if (!row || !row.dataset.href) return;
    if (event.target.closest("a, button, input, select, textarea, summary, label")) return;
    if (String(window.getSelection() || "")) return;
    event.preventDefault();
    follow(row.dataset.href);
  });

  //
  // The back button walks the views back, which is the whole reason they are
  // in the address. Answered the same way as a click, so going back is as
  // still as going forward.
  //
  window.addEventListener("popstate", () => {
    swap(window.location.href, false).catch(() => window.location.reload());
  });

  //
  // A finished job redraws the page's content in place (waiting.js), and the
  // region it brings is new.
  //
  document.addEventListener("haprion:redrawn", () => {
    wireDeletion();
    wireRefresh();
  });

  wireDeletion();
  wireRefresh();
})();
