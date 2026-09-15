(() => {
  "use strict";

  //
  // One provider profile field on the certificate form, drawn for whichever
  // CA is chosen: the DNS select under DNS-01, the NDES select under
  // Microsoft AD CS, and under HTTP-01 the DNS select greyed in place, the
  // way the object form treats the tcp port, so choosing a challenge does
  // not change the page's height under the reader.
  //
  // The browser is a convenience here and never the control. A disabled
  // select is not submitted, and the server refuses a profile with HTTP-01
  // and requires one with the other two, so a submission with the field
  // re-enabled by hand is answered the same way as any other bad form.
  //
  const wire = () => {
    const methods = Array.from(document.querySelectorAll("input[name='method']"));
    const field = document.querySelector("[data-profile-field]");
    if (!methods.length || !field) return;
    const profile = field.querySelector("select[name='dns_profile']");
    const ndesProfile = field.querySelector("select[name='ndes_profile']");
    const hints = Array.from(field.querySelectorAll("[data-profile-hint]"));
    if (!profile) return;

    const apply = () => {
      const chosen = methods.find((method) => method.checked);
      const method = chosen ? chosen.value : "dns-01";
      profile.disabled = method !== "dns-01";
      profile.hidden = method === "ndes";
      if (ndesProfile) {
        ndesProfile.disabled = method !== "ndes";
        ndesProfile.hidden = method !== "ndes";
      }
      hints.forEach((hint) => { hint.hidden = hint.dataset.profileHint !== method; });
    };
    methods.forEach((method) => method.addEventListener("change", apply));
    apply();
  };

  window.addEventListener("DOMContentLoaded", wire);
})();
