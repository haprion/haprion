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

  window.addEventListener("DOMContentLoaded", wire);
})();
