(() => {
  //
  // The listing is rendered once and then sits still, which is right for every
  // state on it but one. "Waiting for publish" resolves in a second or two, and
  // that is exactly the second somebody is looking at the page - so a reader who
  // stays put watches a spinner that has nothing left to say, and only finds out
  // it finished by leaving and coming back.
  //
  // So the page reloads itself, but only while there is something in flight: the
  // spinner is the signal, and when the server stops drawing one the reloading
  // stops with it. Nothing here polls an endpoint or holds a connection open -
  // it asks for the same page again, which is the only thing that can render the
  // new state anyway.
  //
  const INTERVAL = 3000;

  //
  // Bounded, because a job that never finishes must not turn into a page that
  // reloads forever. Roughly a minute of watching, after which somebody who is
  // still interested can reload it themselves - and a job still running after
  // that has a problem the jobs page describes better than this one.
  //
  const LIMIT = 20;

  const KEY = "waiting-reloads";

  const count = () => {
    try {
      return Number(sessionStorage.getItem(KEY)) || 0;
    } catch (error) {
      //
      // A browser that refuses storage still gets one reload rather than an
      // endless run: without a count there is no way to stop, so it does not
      // start.
      //
      return LIMIT;
    }
  };

  const remember = (value) => {
    try {
      sessionStorage.setItem(KEY, String(value));
    } catch (error) {
      // As above.
    }
  };

  window.addEventListener("DOMContentLoaded", () => {
    const waiting = document.querySelector(".badge-spinner");
    if (!waiting) {
      remember(0);
      return;
    }

    const seen = count();
    if (seen >= LIMIT) return;

    window.setTimeout(() => {
      remember(seen + 1);
      window.location.reload();
    }, INTERVAL);
  });
})();
