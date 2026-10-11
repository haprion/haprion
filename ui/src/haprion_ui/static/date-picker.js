(() => {
  "use strict";

  // The date and time picker beside a From or To field (traffic logs, WAF
  // logs, Events -> Audit). A month at a time, stepped with the arrows, inside
  // the window the page allows: the logs keep 14 days, the audit record two
  // years, and a grid of every day in two years would be 730 buttons (26-10-11).
  //
  // One listener on the document for each kind of event rather than one per
  // picker: the traffic log page replaces its filters in place, and listeners
  // on the old ones would leave the new ones dead.
  const PICKER = "[data-log-date-picker]";
  const MONTHS = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
  ];
  const two = (value) => String(value).padStart(2, "0");
  const parsed = (value) => {
    const match = /^(\d{2})-(\d{2})-(\d{2}) ([01]\d|2[0-3]):([0-5]\d)$/.exec(value || "");
    return match
      ? { date: `${match[1]}-${match[2]}-${match[3]}`, hour: match[4], minute: match[5] }
      : null;
  };
  // yy-mm-dd and yy-mm compare correctly as text, which is all the window needs.
  const day = (year, month, date) => `${two(year % 100)}-${two(month + 1)}-${two(date)}`;
  const monthOf = (value) => value.slice(0, 5);

  const close = (except) => {
    document.querySelectorAll(PICKER).forEach((picker) => {
      if (picker === except) return;
      const panel = picker.querySelector(".log-calendar");
      const input = picker.querySelector("input");
      if (panel) panel.hidden = true;
      if (input) input.setAttribute("aria-expanded", "false");
    });
  };

  const fill = (select, count) => {
    if (select.options.length) return;
    for (let value = 0; value < count; value += 1) select.add(new Option(two(value), two(value)));
  };

  const render = (picker) => {
    const shown = picker.dataset.month || "";
    const first = (picker.dataset.min || "").slice(0, 8);
    const last = (picker.dataset.max || "").slice(0, 8);
    const year = 2000 + Number(shown.slice(0, 2));
    const month = Number(shown.slice(3, 5)) - 1;
    const label = picker.querySelector("[data-log-month-label]");
    if (label) label.textContent = `${MONTHS[month]} ${year}`;
    const earlier = picker.querySelector('[data-log-month-step="-1"]');
    const later = picker.querySelector('[data-log-month-step="1"]');
    if (earlier) earlier.disabled = shown <= monthOf(first);
    if (later) later.disabled = shown >= monthOf(last);
    const grid = picker.querySelector("[data-log-days]");
    if (!grid) return;
    grid.replaceChildren();
    const lead = (new Date(year, month, 1).getDay() + 6) % 7;
    for (let blank = 0; blank < lead; blank += 1) grid.append(document.createElement("span"));
    const length = new Date(year, month + 1, 0).getDate();
    for (let date = 1; date <= length; date += 1) {
      const value = day(year, month, date);
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = String(date);
      button.dataset.logDay = value;
      button.setAttribute("aria-label", value);
      button.disabled = value < first || value > last;
      if (value === last) button.classList.add("is-today");
      button.setAttribute("aria-pressed", String(value === picker.dataset.selected));
      grid.append(button);
    }
  };

  const open = (picker) => {
    close(picker);
    const input = picker.querySelector("input");
    const panel = picker.querySelector(".log-calendar");
    const hour = picker.querySelector("[data-log-hour]");
    const minute = picker.querySelector("[data-log-minute]");
    if (!input || !panel || !hour || !minute) return;
    fill(hour, 24);
    fill(minute, 60);
    const first = (picker.dataset.min || "").slice(0, 8);
    const last = (picker.dataset.max || "").slice(0, 8);
    let value = parsed(input.value);
    if (!value || value.date < first || value.date > last) value = parsed(picker.dataset.default);
    if (value) {
      picker.dataset.selected = value.date;
      picker.dataset.month = monthOf(value.date);
      hour.value = value.hour;
      minute.value = value.minute;
    } else {
      picker.dataset.selected = "";
      picker.dataset.month = monthOf(last);
    }
    render(picker);
    panel.hidden = false;
    input.setAttribute("aria-expanded", "true");
  };

  const step = (picker, by) => {
    const shown = picker.dataset.month || "";
    const moved = new Date(2000 + Number(shown.slice(0, 2)), Number(shown.slice(3, 5)) - 1 + by, 1);
    picker.dataset.month = `${two(moved.getFullYear() % 100)}-${two(moved.getMonth() + 1)}`;
    render(picker);
  };

  document.addEventListener("click", (event) => {
    const picker = event.target.closest?.(PICKER);
    if (!picker) {
      close(null);
      return;
    }
    const input = picker.querySelector("input");
    if (event.target === input) {
      open(picker);
      return;
    }
    const stepper = event.target.closest("[data-log-month-step]");
    if (stepper) {
      step(picker, Number(stepper.dataset.logMonthStep));
      return;
    }
    const chosen = event.target.closest("[data-log-day]");
    if (chosen && !chosen.disabled) {
      picker.dataset.selected = chosen.dataset.logDay || "";
      render(picker);
      return;
    }
    if (event.target.closest("[data-log-clear]")) {
      input.value = "";
      close(null);
      return;
    }
    if (event.target.closest("[data-log-apply]")) {
      if (!picker.dataset.selected) return;
      const hour = picker.querySelector("[data-log-hour]");
      const minute = picker.querySelector("[data-log-minute]");
      input.value = `${picker.dataset.selected} ${hour.value}:${minute.value}`;
      close(null);
      input.focus();
    }
  });

  document.addEventListener("keydown", (event) => {
    const picker = event.target.closest?.(PICKER);
    if (event.key === "Escape") {
      close(null);
      return;
    }
    if (picker && event.key === "ArrowDown" && event.target === picker.querySelector("input")) {
      event.preventDefault();
      open(picker);
    }
  });
})();
