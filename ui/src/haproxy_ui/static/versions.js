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
  // On load, and again when waiting.js has swapped in the page's content.
  //
  const wireAll = () => document.querySelectorAll("[data-version-list]").forEach(page);
  window.addEventListener("DOMContentLoaded", wireAll);
  document.addEventListener("haproxy-ui:redrawn", wireAll);
})();
