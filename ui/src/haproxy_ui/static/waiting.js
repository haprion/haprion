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

  const ROWS = "/proxies/rows";
  const BUSY = "/clusters/busy";

  //
  // Two pages, two ways of being out of date.
  //
  // The listing has rows that move, and they are swapped in place. Every other
  // page draws a spinner where its buttons were, and what it needs back is
  // those buttons - a form carrying a CSRF token and a fresh idempotency key,
  // neither of which a browser may mint. So that page asks the server for
  // itself again, once, at the moment the answer changed, and swaps in what
  // came back. It is a redraw, but one per finished job rather than one every
  // few seconds.
  //
  const rows = () => document.querySelectorAll("tbody[data-cluster]").length > 0;

  //
  // What the page was drawn with: the clusters it is showing as busy.
  //
  const drawnBusy = () =>
    new Set(Array.from(document.querySelectorAll("[data-busy]"), (el) => el.dataset.busy));

  //
  // What is still on its way: a draft, a publish in flight, an object the nodes
  // are not serving yet, or a job this page is watching. When the server stops
  // drawing one of these there is nothing left to wait for, and the asking
  // stops with it.
  //
  //
  // When each cluster on this page was last read. A job finishing and the
  // poller seeing what it did are two moments, and only the first is a job -
  // so a page reloaded on the job alone shows the deploy's buttons back and
  // every number beside them still describing the release before it.
  //
  const drawnObserved = () =>
    new Map(
      Array.from(document.querySelectorAll("[data-observed]"), (el) => [
        el.dataset.observed,
        el.dataset.observed,
      ]),
    );

  //
  // Set when a job finishes, cleared when the reading that followed it arrives.
  // Without it the page would stop asking the moment the spinner went, which is
  // one poll too early.
  //
  const WATCH = "waiting-observe";

  const watching = () => {
    try {
      return sessionStorage.getItem(WATCH) === "1";
    } catch (error) {
      return false;
    }
  };

  const watch = (on) => {
    try {
      if (on) sessionStorage.setItem(WATCH, "1");
      else sessionStorage.removeItem(WATCH);
    } catch (error) {
      // A browser that refuses storage simply stops at the spinner, as before.
    }
  };

  const pending = () =>
    document.querySelectorAll("tr.proxy-draft, tr.proxy-waiting").length > 0 ||
    drawnBusy().size > 0 ||
    watching();

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

  //
  // The page asked for again and its content swapped in, instead of a reload
  // (live.js). A reload blanked the page and drew it again a few seconds after
  // Back up now - twice, once for the job and once for the reading after it -
  // and closed everything the reader had opened.
  //
  const redraw = () => {
    if (!window.haproxyUi) {
      window.location.reload();
      return;
    }
    window.haproxyUi.redraw().then(() => {
      asked = 0;
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
    fetch(rows() ? ROWS : BUSY, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    })
      .then((response) => (response.ok ? response.json() : null))
      .then((payload) => {
        if (!payload) return;
        if (rows()) {
          apply(payload);
          return;
        }
        //
        // Reloaded only when the answer differs from what is on the screen. A
        // cluster that is still busy leaves the page alone; one that has
        // finished, or a new one that has started, is a page that no longer
        // describes anything true.
        //
        const busy = new Set(Object.keys(payload.busy || {}));
        const drawn = drawnBusy();
        const same = busy.size === drawn.size && Array.from(drawn).every((one) => busy.has(one));
        if (!same) {
          //
          // A job started or finished. The page is redrawn, and it keeps
          // asking afterwards: what the job did is not on the screen until the
          // poller has read the nodes again.
          //
          watch(true);
          redraw();
          return;
        }
        if (!watching()) return;
        const readings = payload.observed || {};
        const drawnReadings = drawnObserved();
        const moved = Object.keys(readings).some(
          (cluster) => readings[cluster] && !drawnReadings.has(readings[cluster]),
        );
        if (moved) {
          watch(false);
          redraw();
        }
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
