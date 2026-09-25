(() => {
  //
  // The schedule form carries fields for all three frequencies, because the
  // server refuses nothing it did not ask for and ignores what the chosen
  // frequency does not use. What this does is hide the two that do not apply,
  // so a daily schedule is not offered a weekday row it would not read.
  // Without it the form is complete and merely longer.
  //
  const wire = (form) => {
    const frequency = form.querySelector("[data-schedule-frequency]");
    if (!frequency) return;
    const parts = Array.from(form.querySelectorAll("[data-schedule-when]"));
    const show = () => {
      parts.forEach((part) => {
        part.hidden = part.dataset.scheduleWhen !== frequency.value;
      });
    };
    frequency.addEventListener("change", show);
    show();
  };

  //
  // Back up now, and the job finishing, both redraw the page, and a redrawn
  // page arrives with every archive list closed and on its first page. What the
  // reader had open is kept per cluster for the tab, so the redraw leaves the
  // view as it was. A browser that refuses storage gets the closed list.
  //
  const VIEW = "haproxy-ui.backups.archive-view";
  const POSITION = "haproxy-ui.backups.position";

  const readViews = () => {
    try {
      return JSON.parse(sessionStorage.getItem(VIEW) || "{}") || {};
    } catch (error) {
      return {};
    }
  };

  const keepView = (cluster, view) => {
    try {
      const views = readViews();
      views[cluster] = view;
      sessionStorage.setItem(VIEW, JSON.stringify(views));
    } catch (error) {
      // As above.
    }
  };

  //
  // A reload keeps its place by itself; the form's redirect lands at the top.
  //
  const keepPosition = () => {
    document.querySelectorAll("[data-backup-now]").forEach((form) => {
      form.addEventListener("submit", () => {
        try {
          sessionStorage.setItem(POSITION, String(window.scrollY));
        } catch (error) {
          // As above.
        }
      });
    });
    try {
      const saved = sessionStorage.getItem(POSITION);
      sessionStorage.removeItem(POSITION);
      if (saved !== null && Number.isFinite(Number(saved))) {
        window.scrollTo(0, Number(saved));
      }
    } catch (error) {
      // As above.
    }
  };

  //
  // The archive list arrives whole, each row marked with its page, and the
  // server has already hidden every page but the first. Without this the
  // first ten per node are still there and the rest are simply not offered.
  //
  const page = (list) => {
    const rows = Array.from(list.querySelectorAll("[data-archive-page]"));
    const range = list.querySelector("[data-archive-page-range]");
    const newer = list.querySelector("[data-archive-page-previous]");
    const older = list.querySelector("[data-archive-page-next]");
    const frame = list.querySelector(".table-scroll");
    const cluster = list.dataset.archiveCluster || "";
    const kept = readViews()[cluster] || {};
    const remember = () => keepView(cluster, { open: list.open, page: current });
    list.open = Boolean(kept.open);
    list.addEventListener("toggle", remember);
    //
    // The toggle event is queued, not immediate: a close followed at once by a
    // redraw would otherwise bring the list back open.
    //
    window.addEventListener("pagehide", remember);
    const perPage = Number(list.dataset.archivePerPage) || 10;
    const deepest = Number(list.dataset.archiveDeepest) || 0;
    const pages = Math.max(Math.ceil(deepest / perPage), 1);
    let current = newer && older ? Math.min(Math.max(Number(kept.page) || 0, 0), pages - 1) : 0;
    if (!newer || !older) return;
    const show = () => {
      rows.forEach((row) => {
        row.hidden = Number(row.dataset.archivePage) !== current;
      });
      const first = current * perPage + 1;
      const last = Math.min((current + 1) * perPage, deepest);
      if (range) range.textContent = `Archives ${first}–${last} per node · page ${current + 1} of ${pages}`;
      newer.disabled = current === 0;
      older.disabled = current >= pages - 1;
      remember();
    };
    newer.addEventListener("click", () => {
      current = Math.max(current - 1, 0);
      show();
    });
    older.addEventListener("click", () => {
      //
      // The last page is usually shorter. Holding the first page's height keeps
      // the buttons where the pointer already is, instead of the list shrinking
      // under it and the next click landing somewhere else.
      //
      if (current === 0 && frame) frame.style.minHeight = `${frame.offsetHeight}px`;
      current = Math.min(current + 1, pages - 1);
      show();
    });
    show();
  };

  window.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("[data-schedule-form]").forEach(wire);
    document.querySelectorAll("[data-archive-list]").forEach(page);
    keepPosition();
  });
})();
