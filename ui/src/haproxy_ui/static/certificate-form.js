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
    const keyType = field.querySelector("select[name='key_type']");
    const title = field.querySelector("#profile-field-title");
    const hints = Array.from(field.querySelectorAll("[data-profile-hint]"));
    if (!profile) return;

    //
    // The CSR method (C9b) has no profile: the same field shows the key
    // type instead, under the same title element, so the page keeps its
    // height and the reader keeps their place.
    //
    const apply = () => {
      const chosen = methods.find((method) => method.checked);
      const method = chosen ? chosen.value : "dns-01";
      profile.disabled = method !== "dns-01";
      profile.hidden = method === "ndes" || method === "csr";
      if (ndesProfile) {
        ndesProfile.disabled = method !== "ndes";
        ndesProfile.hidden = method !== "ndes";
      }
      if (keyType) {
        keyType.disabled = method !== "csr";
        keyType.hidden = method !== "csr";
      }
      if (title) {
        title.textContent = method === "csr" ? title.dataset.keyTitle : title.dataset.profileTitle;
      }
      hints.forEach((hint) => { hint.hidden = hint.dataset.profileHint !== method; });
    };
    methods.forEach((method) => method.addEventListener("change", apply));
    apply();
  };

  //
  // The kind switch is a link to the other form; what is already filled in
  // goes with it (2026-10-06) - the name, the CA and its profile - so
  // changing kind does not empty the form. Disabled fields stay behind, the
  // way a submission leaves them.
  //
  const CARRIED = ["domain", "method", "dns_profile", "ndes_profile", "key_type"];
  const carryForm = () => {
    const form = document.querySelector("input[name='domain']")?.form;
    if (!form) return;
    document.querySelectorAll("a[data-carry-form]").forEach((link) => {
      link.addEventListener("click", () => {
        const target = new URL(link.getAttribute("href"), window.location.href);
        const filled = new FormData(form);
        CARRIED.forEach((name) => {
          const value = String(filled.get(name) || "").trim();
          if (value) target.searchParams.set(name, value);
        });
        link.href = target.toString();
      });
    });
  };

  window.addEventListener("DOMContentLoaded", wire);
  window.addEventListener("DOMContentLoaded", carryForm);
})();
