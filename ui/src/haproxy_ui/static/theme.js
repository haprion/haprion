(() => {
  "use strict";

  //
  // The theme lives in a cookie rather than in localStorage, because the server
  // has to know it. Anything the browser alone knows is applied after the first
  // paint at the earliest, and between two documents the browser paints its own
  // light canvas - which is a flash on every navigation, and every tab here is
  // a full page load. base.html renders data-theme from this cookie, so the
  // document is never unstyled. This file only maintains it and wires up the
  // toggle.
  //
  const name = "haproxy_ui_theme";
  const legacyKey = "haproxy-manager-theme";
  const themes = ["light", "dark"];

  const readCookie = () => {
    const match = document.cookie.match(/(?:^|;\s*)haproxy_ui_theme=([^;]*)/);
    return match ? decodeURIComponent(match[1]) : "";
  };

  const writeCookie = (theme) => {
    //
    // Secure only where it can be, so the development interface over a plain
    // loopback tunnel keeps working. A refused theme cookie is a cosmetic
    // failure, but a silent one is still worth not writing.
    //
    const secure = window.location.protocol === "https:" ? "; secure" : "";
    document.cookie = `${name}=${theme}; path=/; max-age=31536000; samesite=lax${secure}`;
  };

  let selected = readCookie();
  if (!themes.includes(selected)) {
    selected = "light";
    try {
      // One-time adoption of the choice the previous localStorage version kept.
      const stored = window.localStorage.getItem(legacyKey);
      if (stored && themes.includes(stored)) selected = stored;
    } catch (_) {
      // A denied storage API changes persistence, never whether the page works.
    }
    writeCookie(selected);
  }

  const apply = (theme) => {
    document.documentElement.setAttribute("data-theme", theme);

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
      writeCookie(selected);
      apply(selected);
    });
  });
})();
