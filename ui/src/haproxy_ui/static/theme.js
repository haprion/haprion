(() => {
  "use strict";

  const key = "haproxy-manager-theme";
  const themes = ["system", "light", "dark"];
  let selected = "system";

  try {
    const stored = window.localStorage.getItem(key);
    if (stored && themes.includes(stored)) selected = stored;
  } catch (_) {
    // A denied storage API changes persistence, never whether the page works.
  }

  const apply = (theme) => {
    if (theme === "system") {
      document.documentElement.removeAttribute("data-theme");
    } else {
      document.documentElement.setAttribute("data-theme", theme);
    }

    const button = document.querySelector("[data-theme-toggle]");
    const label = document.querySelector("[data-theme-label]");
    if (button) {
      const next = themes[(themes.indexOf(theme) + 1) % themes.length];
      button.setAttribute("aria-label", `Theme: ${theme}. Switch to ${next}`);
      button.setAttribute("title", `Theme: ${theme}. Switch to ${next}`);
    }
    if (label) label.textContent = theme[0].toUpperCase() + theme.slice(1);
  };

  apply(selected);
  window.addEventListener("DOMContentLoaded", () => {
    apply(selected);
    const button = document.querySelector("[data-theme-toggle]");
    if (!button) return;
    button.addEventListener("click", () => {
      selected = themes[(themes.indexOf(selected) + 1) % themes.length];
      try {
        window.localStorage.setItem(key, selected);
      } catch (_) {
        // The selected theme still applies for this page view.
      }
      apply(selected);
    });
  });
})();
