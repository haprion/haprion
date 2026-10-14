(() => {
  //
  // A page with something moving on it - a job queued or running, a restore
  // under way, a certificate being issued - used to reload itself every few
  // seconds until it was done. Each reload blanked the page and drew it again:
  // it blinked, closed the diagnostics somebody had opened to read why a job
  // failed, and threw away a form half filled in.
  //
  // So the page asks for its own address again and swaps in the content the
  // server rendered, and nothing else. The server still does all the reading;
  // nothing here knows what a job or a certificate is. The meta refresh stays
  // inside <noscript>, so a browser without JavaScript gets the reload it
  // always had.
  //
  // What the reader did to the page is carried over: a <details> they opened
  // stays open, and a field they typed into keeps what they typed. While the
  // cursor is in a field the swap waits, since replacing it would take the
  // field from under their fingers.
  //
  // A page that comes back in another shape - a redirect, a session that
  // expired into the login form - is not patched up. That page is reloaded.
  //
  const REDRAWN = "haprion:redrawn";
  const FIELDS = "input:not([type=hidden]), textarea, select";
  const WAIT = 1000;

  //
  // Fields the reader has changed since the page was drawn, by what they
  // belong to: the form's identity, the field's name and which of that name it
  // is.
  //
  // A form is known by where it posts and what its hidden fields say it is
  // about - the cluster, the operation, the certificate - or by `data-keep`
  // where the page names it outright. Not by its position: the backup page
  // drops a cluster's forms while that cluster has a job and draws them again
  // when it is done, and a value typed for one cluster then landed in the next
  // cluster's form, under that cluster's hidden fields (review 2026-09-28 F04).
  // A form that is no longer on the page takes its values with it.
  //
  // The token and the request key are drawn new with every page, so they say
  // nothing about which form this is.
  //
  const VOLATILE = new Set(["csrf_token", "idempotency_key"]);
  const touched = new Set();

  const identity = (form) => {
    if (form.dataset.keep) return `keep:${form.dataset.keep}`;
    const hidden = Array.from(form.querySelectorAll("input[type=hidden]"))
      .filter((input) => input.name && !VOLATILE.has(input.name))
      .map((input) => `${input.name}=${input.value}`);
    return JSON.stringify([form.getAttribute("action") || "", ...hidden]);
  };

  const place = (field) => {
    const main = document.querySelector("main");
    const form = field.form || field.closest("form");
    const scope = form || main;
    const same = scope
      ? Array.from(scope.querySelectorAll(FIELDS)).filter((other) => other.name === field.name)
      : [];
    if (!form) return JSON.stringify([null, 0, field.name, same.indexOf(field)]);
    const id = identity(form);
    const twins = main ? Array.from(main.querySelectorAll("form")).filter((other) => identity(other) === id) : [];
    return JSON.stringify([id, twins.indexOf(form), field.name, same.indexOf(field)]);
  };

  const find = (root, key) => {
    const [id, twin, name, index] = JSON.parse(key);
    const scope =
      id === null ? root : Array.from(root.querySelectorAll("form")).filter((form) => identity(form) === id)[twin];
    if (!scope) return null;
    const same = Array.from(scope.querySelectorAll(FIELDS)).filter((field) => field.name === name);
    return same[index] || null;
  };

  const remember = (event) => {
    const field = event.target;
    if (!field.matches || !field.matches(FIELDS) || !field.name || !field.closest("main")) return;
    touched.add(place(field));
  };
  document.addEventListener("input", remember);
  document.addEventListener("change", remember);

  const typing = () => {
    const active = document.activeElement;
    return Boolean(active && active.matches && active.matches(FIELDS) && active.closest("main"));
  };

  const carry = (here, fresh) => {
    //
    // Keyed where the page names them (a job's diagnostics), otherwise by
    // position, and by position only when the count still matches - a folded
    // list that gained a row would open the wrong one.
    //
    const keyed = new Map(
      Array.from(here.querySelectorAll("details[data-keep]"), (details) => [details.dataset.keep, details.open]),
    );
    fresh.querySelectorAll("details[data-keep]").forEach((details) => {
      if (keyed.has(details.dataset.keep)) details.open = keyed.get(details.dataset.keep);
    });
    const open = Array.from(here.querySelectorAll("details:not([data-keep])"), (details) => details.open);
    const folds = fresh.querySelectorAll("details:not([data-keep])");
    if (folds.length === open.length) {
      folds.forEach((details, index) => {
        details.open = open[index];
      });
    }
    touched.forEach((key) => {
      const was = find(here, key);
      const now = find(fresh, key);
      if (!was || !now || was.type !== now.type) return;
      if (was.type === "checkbox" || was.type === "radio") now.checked = was.checked;
      else now.value = was.value;
    });
  };

  //
  // An open dialog is a decision being made - the dashboard's Publish & deploy
  // lists what goes out and takes a comment (B257). Swapping the page would
  // close it under the reader, so the swap waits for it as it waits for a
  // field.
  //
  const deciding = () => Boolean(document.querySelector("main dialog[open]"));

  const settled = () =>
    new Promise((resolve) => {
      const check = () => (typing() || deciding() ? window.setTimeout(check, WAIT) : resolve());
      check();
    });

  //
  // Resolves with the page that came back, once it is on the screen. Never
  // resolves when it had to reload instead.
  //
  const redraw = () =>
    settled()
      .then(() =>
        fetch(window.location.href, { credentials: "same-origin", headers: { Accept: "text/html" } }),
      )
      .then((response) => {
        if (!response.ok || response.redirected) throw new Error(String(response.status));
        return response.text();
      })
      .then((text) => {
        const parsed = new DOMParser().parseFromString(text, "text/html");
        const fresh = parsed.querySelector("main");
        const here = document.querySelector("main");
        if (!fresh || !here || parsed.title !== document.title) throw new Error("shape");
        fresh.querySelectorAll("script").forEach((script) => script.remove());
        carry(here, fresh);
        const scrolled = window.scrollY;
        here.replaceWith(fresh);
        if (window.scrollY !== scrolled) window.scrollTo(0, scrolled);
        //
        // The head is not swapped, but its marker says whether the page is
        // still moving, and it should say what the new content says.
        //
        const marker = 'meta[name="haproxy-live"]';
        const kept = document.head.querySelector(marker);
        const now = parsed.head.querySelector(marker);
        if (kept) kept.remove();
        if (now) document.head.appendChild(document.importNode(now, false));
        document.dispatchEvent(new CustomEvent(REDRAWN));
        return parsed;
      })
      .catch(
        () =>
          new Promise(() => {
            window.location.reload();
          }),
      );

  window.haproxyUi = Object.assign(window.haproxyUi || {}, { redraw, REDRAWN });

  //
  // A page that should keep itself current says how often in its head, as
  // `<meta name="haproxy-live" content="seconds">`, and the page that comes
  // back decides whether to go on: when the server stops drawing the marker,
  // there is nothing left to wait for. A hidden tab is nobody watching; it is
  // asked again when it comes back.
  //
  const every = (doc) => {
    const marker = doc.querySelector('meta[name="haproxy-live"]');
    const seconds = marker ? Number(marker.content) : 0;
    return Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : 0;
  };

  const follow = (delay) => {
    if (!delay) return;
    window.setTimeout(() => {
      if (document.hidden) {
        follow(delay);
        return;
      }
      redraw().then((parsed) => follow(every(parsed)));
    }, delay);
  };

  //
  // A page that answers a form is at the address the form posted to. Asking
  // that address again is a GET it does not answer, and the reload that
  // follows sends the form a second time - a second job under the same
  // request key, and gone from the screen whatever the answer showed once,
  // such as a receiver's new password (26-10-14). Such a page keeps still.
  //
  const answered = document.documentElement.hasAttribute("data-answered");

  window.addEventListener("DOMContentLoaded", () => follow(answered ? 0 : every(document)));
})();
