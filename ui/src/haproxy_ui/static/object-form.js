(() => {
  "use strict";

  //
  // One field on the object form has no meaning outside tcp: the port. It is
  // greyed out rather than hidden, so choosing a protocol does not change the
  // page's height under the reader, and the label stays legible as a statement
  // about what the shape above decided.
  //
  // The browser is a convenience here and never the control. `build_document`
  // writes a port only for a tcp object and the engine refuses one on http or
  // https, so a submission with the field re-enabled by hand is answered the
  // same way as any other object that does not parse.
  //
  const wire = () => {
    const protocol = document.querySelector("select[name='protocol']");
    const port = document.querySelector(".tcp-only input[name='tcp_port']");
    if (!protocol || !port) return;

    const label = port.closest(".tcp-only");
    const apply = () => {
      port.disabled = protocol.value !== (label.dataset.protocol || "tcp");
    };
    protocol.addEventListener("change", apply);
    apply();
  };

  //
  // How old a handshake to the backend may be is only a question when there is a
  // handshake. Greyed out for the reason the port and the balancing key are:
  // the field stays where it is and says the choice above decided it.
  //
  // The engine agrees, so the browser is again a convenience and not the
  // control - `build_document` writes no `tls` block at all for a plain HTTP
  // backend, and a policy re-enabled by hand has nothing to attach to.
  //
  //
  // The site's own terms are a question only where there is a handshake to
  // hold to them. Same `disabled` as the TCP port and the balancing key, and
  // the engine agrees: it refuses `tls` on anything but https rather than
  // ignoring it, so the browser is a convenience and not the control.
  //
  const wireListenTlsPolicy = () => {
    const protocol = document.querySelector("select[name='protocol']");
    const policy = document.querySelector("select[name='listen_tls_policy']");
    if (!protocol || !policy) return;

    const apply = () => {
      policy.disabled = protocol.value !== "https";
    };
    protocol.addEventListener("change", apply);
    apply();
  };

  const wireBackendTlsPolicy = () => {
    const tls = document.querySelector("select[name='backend_tls']");
    const policy = document.querySelector("select[name='backend_tls_policy']");
    if (!tls || !policy) return;

    const label = policy.closest("label");
    const apply = () => {
      policy.disabled = !tls.value;
      if (label) label.hidden = !tls.value;
    };
    tls.addEventListener("change", apply);
    apply();
  };

  //
  // The balancing key has nothing to name unless the algorithm hashes
  // something: `hdr` takes a header, `url_param` a query parameter, and the
  // engine refuses a key beside any other algorithm rather than ignoring it.
  // Greyed out for the same reason the port is - the field stays where it is
  // and says the choice above decided it.
  //
  const wireBalanceKey = () => {
    const balance = document.querySelector("select[name='balance']");
    const label = document.querySelector(".keyed-only");
    const key = label && label.querySelector("input[name='balance_key']");
    if (!balance || !key) return;

    const keyed = (label.dataset.balances || "").split(" ").filter(Boolean);
    const apply = () => {
      key.disabled = !keyed.includes(balance.value);
    };
    balance.addEventListener("change", apply);
    apply();
  };

  //
  // And the redirect's own choices - its match mode and its status code -
  // which mean nothing until there is a redirect. Both text fields have to
  // carry something before one is written, so both are watched - and `input`
  // rather than `change`, so the choices stop being greyed out as the location
  // is typed rather than when the field is finally left.
  //
  // The two choices wait for different things, because they are about
  // different fields. The match mode says how the path is read, so a path is
  // all it needs - waiting for the target as well would grey out the choice
  // while somebody is still deciding what the path is. The status code is the
  // answer sent to the target, and has nothing to mean until there is one.
  //
  const wireRedirectStatus = () => {
    const path = document.querySelector("input[name='redirect_path']");
    const location = document.querySelector("input[name='redirect_location']");
    const match = document.querySelector("select[name='redirect_match']");
    const status = document.querySelector("select[name='redirect_status']");
    if (!path || !location || !match || !status) return;

    const apply = () => {
      const written = path.value.trim();
      //
      // Dimmed, not disabled. A disabled select is not submitted at all, so
      // the form would fall back to its default - and for the match mode that
      // default is precisely the answer that makes this shape collide. A cue
      // that quietly changes what gets saved is worse than no cue.
      //
      match.classList.toggle("field-idle", !written);
      status.disabled = !(written && location.value.trim());
    };
    path.addEventListener("input", apply);
    location.addEventListener("input", apply);
    apply();
  };

  //
  // Where the reader was, and only for Validate. That button posts and answers
  // with the same page, so the thing that changed is the part they were looking
  // at when they pressed it, and starting at the top would lose it.
  //
  // Every other button leaves the form. Remembering the position for those was
  // a bug with a delay in it: the value was written on submit, never consumed
  // because the answer was a different page, and then picked up by the next
  // visit to the editor - which opened halfway down, at a position from an
  // earlier session, for somebody who had come to read the form from the start.
  //
  // So a submit that leaves clears it rather than setting it.
  //
  const POSITION = "object-form-scroll";

  //
  // The buttons that answer on this same page. Validate re-renders the form
  // with its verdict; Test health re-renders it with what the nodes just tried.
  // In both cases the reader is looking at something a long way down and the
  // answer arrives where they are looking, so the position is worth keeping.
  // Save, publish and discard leave the page, and a value they stored would be
  // consumed by an unrelated later visit instead.
  //
  // Test health was added to the form without being added here, which is how
  // pressing it threw the reader back to the top of a form they were reading
  // the bottom of. The list is held by a test rather than by memory.
  //
  const STAYS_ON_THIS_PAGE = ["check", "recheck"];

  const keepPosition = () => {
    const form = document.querySelector("form.preview-form");
    if (!form) return;

    form.addEventListener("submit", (event) => {
      //
      // A submit answered in the background never reloads, so a position
      // stored for it would be read by the next, unrelated visit instead.
      //
      if (event.defaultPrevented) return;
      const pressed = event.submitter && event.submitter.value;
      try {
        if (STAYS_ON_THIS_PAGE.includes(pressed)) {
          sessionStorage.setItem(POSITION, String(window.scrollY));
        } else {
          sessionStorage.removeItem(POSITION);
        }
      } catch (error) {
        // A browser that refuses storage still gets a working form.
      }
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
  // "The VIP's own" names an address the reader cannot see, and which one it is
  // depends on the VIP chosen above. The address rides on each option, so the
  // label follows the choice instead of going stale the moment it is changed.
  //
  const wireOwnSource = () => {
    const vip = document.querySelector("select[name='vip']");
    const source = document.querySelector("select[name='source']");
    const own = source && source.querySelector("option[data-label]");
    if (!vip || !own) return;

    const apply = () => {
      const chosen = vip.options[vip.selectedIndex];
      const address = chosen
        ? chosen.dataset.source || (chosen.value ? "" : vip.dataset.defaultSource || "")
        : "";
      own.textContent = address ? `${own.dataset.label} — ${address}` : own.dataset.label;
    };
    vip.addEventListener("change", apply);
    apply();
  };

  //
  // Slow start has to outlast the check interval, and the hint that says so
  // named the interval the page was rendered with. Typing 10s into the field
  // directly above it left the sentence saying 2s until the form was posted -
  // a hint that describes a value the reader can see is wrong is worse than no
  // hint, because it is read as the rule rather than as a stale echo.
  //
  const wireSlowStartHint = () => {
    const interval = document.querySelector("input[name='health_interval']");
    const shown = document.querySelector(".slow-start-interval");
    if (!interval || !shown) return;

    const apply = () => {
      shown.textContent = interval.value.trim() || shown.dataset.default || "";
    };
    interval.addEventListener("input", apply);
    apply();
  };

  //
  // Fields and groups that belong to one shape only - `data-show-when` names the
  // choice and the values it holds for, such as `protocol:http https`. The page
  // arrives already right, rendered by the same rule; this follows the choice as
  // it is changed. One rule for all of them, so a new field that belongs to one
  // shape needs an attribute and not a function here.
  //
  const wireShownWhen = () => {
    const shaped = Array.from(document.querySelectorAll("[data-show-when]"));
    const watched = new Set();
    const apply = () => {
      for (const element of shaped) {
        const [field, values] = element.dataset.showWhen.split(":");
        const choice = document.querySelector(`select[name='${field}']`);
        if (!choice) continue;
        element.hidden = !(values || "").split(" ").includes(choice.value);
      }
    };
    for (const element of shaped) {
      const field = element.dataset.showWhen.split(":")[0];
      const choice = document.querySelector(`select[name='${field}']`);
      if (choice && !watched.has(choice)) {
        watched.add(choice);
        choice.addEventListener("change", apply);
      }
    }
    apply();
  };

  //
  // A folded group's line describes the group as the page was rendered. Once a
  // field inside it is changed that line is about something that is no longer
  // on screen, and a closed group would then say the wrong thing about itself -
  // so it says it has changed instead, until the next Validate writes it anew.
  //
  const wireGroupSummaries = () => {
    for (const group of document.querySelectorAll("details.form-group")) {
      const line = group.querySelector("[data-group-summary]");
      if (!line) continue;
      const mark = () => {
        line.textContent = "Changed — validate to see the result";
        line.classList.add("changed");
      };
      group.addEventListener("input", mark, { once: true });
      group.addEventListener("change", mark, { once: true });
    }
  };

  //
  // Test health check without leaving the page (2026-09-30). The button posted
  // the whole form and the answer was the whole page again, which reloaded it
  // under the reader: scrolled back, groups closed, for one table's worth of
  // news. So the same post is sent in the background and only the health block
  // of the answer replaces this one. The server is asked exactly what it was
  // asked before - same fields, same button, same token - so nothing here
  // decides what a test is.
  //
  // Anything unexpected falls back to the ordinary submit rather than guessing:
  // a refused post, a redirect (an expired session answers with the login
  // page) or an answer without the block.
  //
  const wireRecheck = () => {
    const form = document.querySelector("form.preview-form");
    if (!form || !window.fetch || !window.DOMParser) return;

    let fallback = false;
    form.addEventListener("submit", (event) => {
      const button = event.submitter;
      if (fallback || !button || button.value !== "recheck") return;
      const here = form.querySelector(".node-health");
      if (!here) return;
      event.preventDefault();

      //
      // Encoded the way the form itself posts: `FormData` alone would send
      // multipart, and the server should be asked in the same shape as before.
      //
      const body = new URLSearchParams(new FormData(form, button));
      const label = button.textContent;
      button.disabled = true;
      button.textContent = "Testing…";
      const restore = () => {
        button.disabled = false;
        button.textContent = label;
      };

      //
      // The attribute, not `form.action`: the buttons are named `action`, and a
      // control's name shadows the form's own property of that name - the post
      // went to "[object HTMLButtonElement]" until the browser test caught it.
      //
      const target = new URL(form.getAttribute("action") || "", document.baseURI);
      fetch(target, { method: "POST", body, credentials: "same-origin" })
        .then((response) => {
          if (!response.ok || response.redirected) throw new Error(String(response.status));
          return response.text();
        })
        .then((text) => {
          const fresh = new DOMParser()
            .parseFromString(text, "text/html")
            .querySelector("form.preview-form .node-health");
          if (!fresh) throw new Error("shape");
          here.replaceWith(document.importNode(fresh, true));
          restore();
        })
        .catch(() => {
          restore();
          fallback = true;
          form.requestSubmit(button);
        });
    });
  };

  window.addEventListener("DOMContentLoaded", () => {
    wireRecheck();
    wireShownWhen();
    wireGroupSummaries();
    wire();
    wireBalanceKey();
    wireBackendTlsPolicy();
    wireListenTlsPolicy();
    wireRedirectStatus();
    keepPosition();
    wireOwnSource();
    wireSlowStartHint();
  });
})();
