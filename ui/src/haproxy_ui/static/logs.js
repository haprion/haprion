(() => {
  "use strict";

  const two = (value) => String(value).padStart(2, "0");
  const parsed = (value) => {
    const match = /^(\d{2})-(\d{2})-(\d{2}) ([01]\d|2[0-3]):([0-5]\d)$/.exec(value);
    return match
      ? { date: `${match[1]}-${match[2]}-${match[3]}`, hour: match[4], minute: match[5] }
      : null;
  };

  const closePickers = (except) => {
    document.querySelectorAll("[data-log-date-picker]").forEach((picker) => {
      if (picker === except) return;
      const panel = picker.querySelector(".log-calendar");
      const input = picker.querySelector("input");
      if (panel) panel.hidden = true;
      if (input) input.setAttribute("aria-expanded", "false");
    });
  };

  const buildPicker = (picker) => {
    const input = picker.querySelector("input");
    const panel = picker.querySelector(".log-calendar");
    const hour = picker.querySelector("[data-log-hour]");
    const minute = picker.querySelector("[data-log-minute]");
    const days = Array.from(picker.querySelectorAll("[data-log-day]:not(:disabled)"));
    if (!input || !panel || !hour || !minute || days.length === 0) return;
    const allowed = new Set(days.map((day) => day.dataset.logDay));

    for (let value = 0; value < 24; value += 1) {
      hour.add(new Option(two(value), two(value)));
    }
    for (let value = 0; value < 60; value += 1) {
      minute.add(new Option(two(value), two(value)));
    }

    let selected = "";
    const choose = (date) => {
      selected = date;
      days.forEach((day) => {
        day.setAttribute("aria-pressed", String(day.dataset.logDay === selected));
      });
    };

    const open = () => {
      closePickers(picker);
      let value = parsed(input.value);
      if (!value || !allowed.has(value.date)) value = parsed(picker.dataset.default || "");
      if (value) {
        choose(value.date);
        hour.value = value.hour;
        minute.value = value.minute;
      }
      panel.hidden = false;
      input.setAttribute("aria-expanded", "true");
    };

    input.addEventListener("click", open);
    input.addEventListener("keydown", (event) => {
      if (event.key === "ArrowDown") {
        event.preventDefault();
        open();
      }
      if (event.key === "Escape") {
        panel.hidden = true;
        input.setAttribute("aria-expanded", "false");
      }
    });
    days.forEach((day) => day.addEventListener("click", () => choose(day.dataset.logDay || "")));
    picker.querySelector("[data-log-clear]")?.addEventListener("click", () => {
      input.value = "";
      panel.hidden = true;
      input.setAttribute("aria-expanded", "false");
    });
    picker.querySelector("[data-log-apply]")?.addEventListener("click", () => {
      if (!selected) return;
      input.value = `${selected} ${hour.value}:${minute.value}`;
      panel.hidden = true;
      input.setAttribute("aria-expanded", "false");
      input.focus();
    });
    picker.addEventListener("click", (event) => event.stopPropagation());
  };

  const csvCell = (value) => {
    let safe = String(value ?? "").replace(/\r?\n/g, " ");
    // Spreadsheet applications treat these prefixes as formulas even inside
    // a quoted CSV field. The apostrophe is their standard literal-text mark.
    if (/^[=+\-@\t\r]/.test(safe)) safe = `'${safe}`;
    return `"${safe.replace(/"/g, '""')}"`;
  };

  const buildExport = () => {
    const rows = Array.from(document.querySelectorAll("[data-log-row]"));
    const all = document.querySelector("[data-log-select-all]");
    const button = document.querySelector("[data-log-export]");
    const count = document.querySelector("[data-log-selected-count]");
    if (!all) return;

    const selectedRows = () =>
      rows.filter((row) => row.querySelector("[data-log-select]")?.checked);
    const update = () => {
      const selected = selectedRows().length;
      all.checked = rows.length > 0 && selected === rows.length;
      all.indeterminate = selected > 0 && selected < rows.length;
      all.disabled = rows.length === 0;
      if (button) button.disabled = selected === 0;
      if (count) count.textContent = selected === 0 ? "No rows selected" : `${selected} selected`;
    };

    all.addEventListener("change", () => {
      rows.forEach((row) => {
        const checkbox = row.querySelector("[data-log-select]");
        if (checkbox) checkbox.checked = all.checked;
      });
      update();
    });
    rows.forEach((row) => row.querySelector("[data-log-select]")?.addEventListener("change", update));
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
    update();
  };

  const start = () => {
    document.querySelectorAll("[data-log-date-picker]").forEach(buildPicker);
    document.addEventListener("click", () => closePickers(null));
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") closePickers(null);
    });
    buildExport();
  };

  if (document.readyState === "loading") window.addEventListener("DOMContentLoaded", start);
  else start();
})();
