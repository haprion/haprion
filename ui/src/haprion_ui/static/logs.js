(() => {
  "use strict";

  const REGION = "[data-log-region]";
  const two = (value) => String(value).padStart(2, "0");

  const csvCell = (value) => {
    let safe = String(value ?? "").replace(/\r?\n/g, " ");
    // Spreadsheet applications treat these prefixes as formulas even inside
    // a quoted CSV field. The apostrophe is their standard literal-text mark.
    if (/^[=+\-@\t\r]/.test(safe)) safe = `'${safe}`;
    return `"${safe.replace(/"/g, '""')}"`;
  };

  const buildTableControls = (root) => {
    const rows = Array.from(root.querySelectorAll("[data-log-row]"));
    const all = root.querySelector("[data-log-select-all]");
    const button = root.querySelector("[data-log-export]");
    const count = root.querySelector("[data-log-selected-count]");
    const size = root.querySelector("[data-log-page-size]");
    const range = root.querySelector("[data-log-page-range]");
    const previous = root.querySelector("[data-log-page-previous]");
    const next = root.querySelector("[data-log-page-next]");
    if (!all) return;
    let page = 0;

    const selectedRows = () =>
      rows.filter((row) => row.querySelector("[data-log-select]")?.checked);
    const visibleRows = () => rows.filter((row) => !row.hidden);
    const updateSelection = () => {
      const selected = selectedRows().length;
      const shown = visibleRows();
      const selectedShown = shown.filter(
        (row) => row.querySelector("[data-log-select]")?.checked
      ).length;
      all.checked = shown.length > 0 && selectedShown === shown.length;
      all.indeterminate = selectedShown > 0 && selectedShown < shown.length;
      all.disabled = shown.length === 0;
      if (button) button.disabled = selected === 0;
      if (count) count.textContent = selected === 0 ? "No rows selected" : `${selected} selected`;
    };

    const showPage = () => {
      const pageSize = size ? Number(size.value) : Math.max(rows.length, 1);
      const pages = Math.max(Math.ceil(rows.length / pageSize), 1);
      page = Math.min(page, pages - 1);
      const start = page * pageSize;
      const end = Math.min(start + pageSize, rows.length);
      rows.forEach((row, index) => {
        row.hidden = index < start || index >= end;
      });
      if (range) {
        range.textContent = rows.length === 0 ? "0 of 0" : `${start + 1}–${end} of ${rows.length}`;
      }
      if (previous) previous.disabled = page === 0;
      if (next) next.disabled = page >= pages - 1;
      updateSelection();
    };

    all.addEventListener("change", () => {
      visibleRows().forEach((row) => {
        const checkbox = row.querySelector("[data-log-select]");
        if (checkbox) checkbox.checked = all.checked;
      });
      updateSelection();
    });
    rows.forEach((row) =>
      row.querySelector("[data-log-select]")?.addEventListener("change", updateSelection)
    );
    size?.addEventListener("change", () => {
      page = 0;
      showPage();
    });
    previous?.addEventListener("click", () => {
      page -= 1;
      showPage();
    });
    next?.addEventListener("click", () => {
      page += 1;
      showPage();
    });
    button?.addEventListener("click", () => {
      const headings = [
        "Time",
        "Cluster",
        "Node",
        "Client",
        "Method",
        "Host",
        "Path",
        "Status",
        "Destination",
        "Bytes",
      ];
      const fields = [
        "exportTime",
        "exportCluster",
        "exportNode",
        "exportClient",
        "exportMethod",
        "exportHost",
        "exportPath",
        "exportStatus",
        "exportDestination",
        "exportBytes",
      ];
      const lines = [headings.map(csvCell).join(",")];
      selectedRows().forEach((row) => {
        lines.push(fields.map((field) => csvCell(row.dataset[field])).join(","));
      });
      const blob = new Blob(["\uFEFF", lines.join("\r\n"), "\r\n"], {
        type: "text/csv;charset=utf-8",
      });
      const link = document.createElement("a");
      const now = new Date();
      link.href = URL.createObjectURL(blob);
      link.download =
        `traffic-logs-${now.getFullYear()}${two(now.getMonth() + 1)}${two(now.getDate())}-` +
        `${two(now.getHours())}${two(now.getMinutes())}${two(now.getSeconds())}.csv`;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(link.href), 0);
    });
    showPage();
  };

  const wire = (root) => {
    buildTableControls(root);
  };

  const swap = async (href, push) => {
    const here = document.querySelector(REGION);
    if (!here) throw new Error("missing log region");
    here.setAttribute("aria-busy", "true");
    const answer = await fetch(href, { credentials: "same-origin" });
    if (!answer.ok) throw new Error(String(answer.status));
    const parsedPage = new DOMParser().parseFromString(await answer.text(), "text/html");
    const fresh = parsedPage.querySelector(REGION);
    if (!fresh) throw new Error("unexpected response");
    here.replaceWith(fresh);
    if (push) history.pushState({ logs: true }, "", href);
    wire(fresh);
  };

  const follow = (href) => {
    swap(href, true).catch(() => window.location.assign(href));
  };

  //
  // The warning keeps itself current (26-10-12). It was drawn once with the
  // page, so a node catching up kept saying "9 s ago" and the same byte count
  // for as long as the page was open. Every 15 s, while the tab is visible,
  // the warning alone is asked for and swapped in: the table, a selection and
  // the scroll position are left alone, and a warning somebody has opened
  // stays open. A failed ask - offline, a session that expired - leaves the
  // warning as it was, and the next tick tries again.
  //
  const WARNING = "[data-log-warning]";
  const refreshWarning = async () => {
    const here = document.querySelector(WARNING);
    if (!here || document.hidden) return;
    const answer = await fetch(here.dataset.logWarning, {
      credentials: "same-origin",
      headers: { Accept: "text/html" },
    });
    if (!answer.ok || answer.redirected) return;
    const parsed = new DOMParser().parseFromString(await answer.text(), "text/html");
    const fresh = parsed.querySelector(WARNING);
    //
    // A filter swapped the region in the meantime: that region's warning is
    // newer than this answer, which was for the old one.
    //
    if (!fresh || document.querySelector(WARNING) !== here) return;
    const details = fresh.querySelector("details");
    if (details && here.querySelector("details[open]")) details.open = true;
    here.replaceWith(fresh);
  };

  const start = () => {
    wire(document);
    window.setInterval(() => refreshWarning().catch(() => {}), 15000);
    document.addEventListener("submit", (event) => {
      const form = event.target.closest?.("[data-log-filters]");
      if (!form) return;
      event.preventDefault();
      const href = new URL(form.action, window.location.href);
      href.search = new URLSearchParams(new FormData(form)).toString();
      follow(href.href);
    });
    document.addEventListener("click", (event) => {
      if (event.button !== 0 || event.defaultPrevented) return;
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const link = event.target.closest?.(`[data-log-clear-filters], ${REGION} .sort-link`);
      if (!link) return;
      event.preventDefault();
      follow(link.href);
    });
    window.addEventListener("popstate", () => {
      swap(window.location.href, false).catch(() => window.location.reload());
    });
  };

  if (document.readyState === "loading") window.addEventListener("DOMContentLoaded", start);
  else start();
})();
