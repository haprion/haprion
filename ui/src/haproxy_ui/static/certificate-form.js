(() => {
  "use strict";

  //
  // Two fields on the certificate form belong to one choice each: the DNS
  // provider profile to DNS-01, the NDES provider profile to Microsoft AD CS.
  // Each is greyed out rather than hidden, the way the object form treats the
  // tcp port, so choosing a challenge does not change the page's height
  // under the reader.
  //
  // The browser is a convenience here and never the control. A disabled
  // select is not submitted, and the server refuses a profile with HTTP-01
  // and requires one with DNS-01, so a submission with the field re-enabled
  // by hand is answered the same way as any other bad form.
  //
  const wire = () => {
    const methods = Array.from(document.querySelectorAll("input[name='method']"));
    const profile = document.querySelector(".dns-only select[name='dns_profile']");
    const ndesProfile = document.querySelector(".ndes-only select[name='ndes_profile']");
    if (!methods.length || !profile) return;

    const apply = () => {
      const chosen = methods.find((method) => method.checked);
      profile.disabled = Boolean(chosen) && chosen.value !== "dns-01";
      if (ndesProfile) ndesProfile.disabled = !chosen || chosen.value !== "ndes";
    };
    methods.forEach((method) => method.addEventListener("change", apply));
    apply();
  };

  window.addEventListener("DOMContentLoaded", wire);
})();
