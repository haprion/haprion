(() => {
  //
  // The listing is rendered once and then sits still, which is right for every
  // state on it but the ones that resolve on their own. A publish finishes in a
  // second or two and a deploy in rather longer, and both are exactly the
  // stretch somebody is looking at the page - so a reader who stays put watches
  // a row that has nothing left to say, and only finds out it moved by leaving
  // and coming back.
  //
  // So the rows catch up, and the page does not. Reloading it lost the scroll
  // position and blinked six cards and a heading for one changed cell; this
  // asks for the rows alone and swaps them in. The markup comes from the same
  // macro the page rendered, so a refreshed row cannot differ in shape from the
  // one it replaces.
  //
  const INTERVAL = 4000;

  //
  // Bounded, because work that never finishes must not turn into a page that
  // asks forever. Roughly five minutes, which covers a deploy; after that
  // somebody still watching can reload, and a job that has not finished by then
  // has a problem the jobs page describes better than this one.
  //
  const LIMIT = 75;

  const ENDPOINT = "/proxies/rows";

  //
  // What is still on its way: a draft, a publish in flight, an object the nodes
  // are not serving yet. When the server stops drawing one of these there is
  // nothing left to wait for, and the asking stops with it.
  //
  const pending = () => document.querySelectorAll("tr.proxy-draft, tr.proxy-waiting").length > 0;

  const apply = (payload) => {
    const clusters = payload && payload.clusters ? payload.clusters : {};
    Object.keys(clusters).forEach((cluster) => {
      //
      // Attribute selector rather than an id: a cluster name is somebody's
      // configuration and need not be a valid identifier.
      //
      const body = document.querySelector(`tbody[data-cluster="${CSS.escape(cluster)}"]`);
      if (body && body.innerHTML !== clusters[cluster]) body.innerHTML = clusters[cluster];
    });
    const counts = payload && payload.counts ? payload.counts : {};
    Object.keys(counts).forEach((name) => {
      const cell = document.querySelector(`[data-count="${name}"]`);
      if (cell) cell.textContent = String(counts[name]);
    });
  };

  let asked = 0;

  const tick = () => {
    if (!pending() || asked >= LIMIT) return;
    asked += 1;
    //
    // A hidden tab is nobody watching. It is asked again when it comes back,
    // rather than kept up to date for a reader who is not there.
    //
    if (document.hidden) {
      window.setTimeout(tick, INTERVAL);
      return;
    }
    fetch(ENDPOINT, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then((response) => (response.ok ? response.json() : null))
      .then((payload) => {
        if (payload) apply(payload);
      })
      .catch(() => {
        //
        // A refresh that fails changes nothing on the page. The row keeps
        // saying what the server last said, which is true, and the next tick
        // tries again.
      })
      .finally(() => {
        window.setTimeout(tick, INTERVAL);
      });
  };

  window.addEventListener("DOMContentLoaded", () => {
    if (pending()) window.setTimeout(tick, INTERVAL);
  });
})();
