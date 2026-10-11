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
  // The page of each table the address shows (B222), so a refresh replaces
  // the rows on screen rather than the first hundred. Only those, each checked
  // as a cluster name and a whole number, rather than the address passed on;
  // the order travels in the cookie the heading set.
  const PAGE = /^page-[a-z0-9][a-z0-9_-]{0,31}$/;
  // And the objects using one VIP, source or group (26-10-11), or a refresh
  // would swap the whole cluster's rows into a filtered table. The server
  // checks the values; these are only the names it reads.
  const USED = new Set(["cluster", "vip", "source", "group"]);
  const pages = () => {
    const kept = new URLSearchParams();
    for (const [key, value] of new URLSearchParams(window.location.search)) {
      const number = Number.parseInt(value, 10);
      if (PAGE.test(key) && Number.isInteger(number) && number > 0) kept.set(key, String(number));
      if (USED.has(key) && value.length <= 255) kept.set(key, value);
    }
    const query = kept.toString();
    return query ? `?${query}` : "";
  };

  //
  // What the page was drawn with: the clusters it is showing as busy.
  //
  const drawnBusy = () =>
    new Set(Array.from(document.querySelectorAll("[data-busy]"), (el) => el.dataset.busy));

  //
  // Set while a cluster is catching up and the page on screen was drawn
  // before it had: drawn from readings the job's change is not in yet, with
  // no spinner left to say so. Cleared by the redraw once it has caught up.
  // The content is redrawn in place and this script stays, so the page's own
  // memory is enough; nothing carries it to the next page.
  //
  let watched = false;

  const watching = () => watched;

  const watch = (on) => {
    watched = on;
  };

  //
  // What is still on its way: a draft, a publish in flight, an object the nodes
  // are not serving yet, or a job this page is watching. When the server stops
  // drawing one of these there is nothing left to wait for, and the asking
  // stops with it.
  //
  const drawnPending = () =>
    document.querySelectorAll("tr.proxy-draft, tr.proxy-waiting").length > 0 ||
    drawnBusy().size > 0;

  const pending = () => drawnPending() || watching();

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
    fetch(rows() ? ROWS + pages() : BUSY, {
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
        // Redrawn only when the answer differs from what is on the screen. A
        // cluster that is still busy leaves the page alone; one that has
        // finished, or a new one that has started, is a page that no longer
        // describes anything true.
        //
        const busy = new Set(Object.keys(payload.busy || {}));
        const catching = new Set(payload.catching_up || []);
        const drawn = drawnBusy();
        const same = busy.size === drawn.size && Array.from(drawn).every((one) => busy.has(one));
        if (!same) {
          //
          // A job finishing and the poller reading what it did are two
          // moments (0068). The spinner stays until the second: redrawn on
          // the first, the page had the buttons back beside counts from
          // before the job - Publish & deploy offering what it had just done.
          //
          if (Array.from(drawn).some((one) => !busy.has(one) && catching.has(one))) return;
          watch(false);
          redraw();
          return;
        }
        if (watching() && catching.size === 0) {
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

  //
  // A page drawn while a cluster was catching up - the answer to a job that
  // ended before the browser was back, or a reload at that moment - has no
  // spinner to watch, yet shows readings from before the job. It asks once,
  // and if the server says so it waits for the reading like any other.
  //
  const settle = () => {
    fetch(BUSY, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then((response) => (response.ok ? response.json() : null))
      .then((payload) => {
        const catching = payload && payload.catching_up ? payload.catching_up : [];
        watch(catching.length > 0);
        if (catching.length > 0) window.setTimeout(tick, INTERVAL);
      })
      .catch(() => {
        // Nothing learnt is nothing to wait for; the page stays as drawn.
      });
  };

  window.addEventListener("DOMContentLoaded", () => {
    if (drawnPending()) window.setTimeout(tick, INTERVAL);
    else if (!rows()) settle();
  });
})();
