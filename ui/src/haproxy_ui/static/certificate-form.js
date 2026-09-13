(() => {
  "use strict";

  //
  // One field on the certificate form has no meaning outside DNS-01: the
  // provider profile. It is greyed out rather than hidden, the way the object
  // form treats the tcp port, so choosing a challenge does not change the
  // page's height under the reader.
  //
  // The browser is a convenience here and never the control. A disabled
  // select is not submitted, and the server refuses a profile with HTTP-01
  // and requires one with DNS-01, so a submission with the field re-enabled
  // by hand is answered the same way as any other bad form.
  //
  const wire = () => {
    const methods = Array.from(document.querySelectorAll("input[name='method']"));
    const profile = document.querySelector(".dns-only select[name='dns_profile']");
    if (!methods.length || !profile) return;

    const apply = () => {
      const chosen = methods.find((method) => method.checked);
      profile.disabled = Boolean(chosen) && chosen.value !== "dns-01";
    };
    methods.forEach((method) => method.addEventListener("change", apply));
    apply();
  };

  window.addEventListener("DOMContentLoaded", wire);
})();
