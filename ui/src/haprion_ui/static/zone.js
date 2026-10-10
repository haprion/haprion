(() => {
  "use strict";

  //
  // Every time on the interface is drawn on the server - the traffic card's
  // axis, the log filter, the fourteen-day window - so the server has to know
  // the reader's clock rather than the browser correcting it afterwards. This
  // hands the browser's own IANA zone over in a cookie, read on the next
  // request. Until it has, and wherever it cannot, the pages keep the manager's
  // clock. The login page carries this too, so the first page after signing in
  // is already in the reader's zone.
  //
  const name = "haprion_ui_zone";
  const shape = /^(?=.{1,64}$)[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+){0,2}$/;

  let zone = "";
  try {
    zone = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  } catch (_) {
    return;
  }
  if (!shape.test(zone)) return;

  const match = document.cookie.match(/(?:^|;\s*)haprion_ui_zone=([^;]*)/);
  if (match && match[1] === zone) return;

  // Written raw: the shape above holds only characters a cookie value allows.
  const secure = window.location.protocol === "https:" ? "; secure" : "";
  document.cookie = `${name}=${zone}; path=/; max-age=31536000; samesite=lax${secure}`;
})();
