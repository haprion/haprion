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
  // And the redirect's status code, which means nothing until there is a
  // redirect. Both fields have to carry something before one is written, so
  // both are watched - and `input` rather than `change`, so the code stops
  // being greyed out as the location is typed rather than when the field is
  // finally left.
  //
  const wireRedirectStatus = () => {
    const path = document.querySelector("input[name='redirect_path']");
    const location = document.querySelector("input[name='redirect_location']");
    const status = document.querySelector(".redirect-only select[name='redirect_status']");
    if (!path || !location || !status) return;

    const apply = () => {
      status.disabled = !(path.value.trim() && location.value.trim());
    };
    path.addEventListener("input", apply);
    location.addEventListener("input", apply);
    apply();
  };

  window.addEventListener("DOMContentLoaded", () => {
    wire();
    wireBalanceKey();
    wireRedirectStatus();
  });
})();
