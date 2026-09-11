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

    const apply = () => {
      policy.disabled = !tls.value;
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

  window.addEventListener("DOMContentLoaded", () => {
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
