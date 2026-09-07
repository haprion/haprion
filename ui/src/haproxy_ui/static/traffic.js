(() => {
  //
  // The traffic card's reading of one bucket, and the range a reader marks.
  //
  // The readings were carried by SVG `<title>`, which is the browser's own
  // tooltip and correct in every way but two: it waits about a second before
  // it appears, and it is a floating box. A box wide enough to hold seven
  // figures cannot be placed anywhere over a card this size without covering
  // either the scale it is read against or the line it is read from - which is
  // how it was, at both ends of every window.
  //
  // So the figures are written into the row the card already has beneath the
  // line. It is where the window's own figures are printed, the numbers land
  // in the same place for every bucket - which is what makes two of them
  // comparable by eye - and nothing is covered by anything.
  //
  // The `<title>` elements are removed as this script takes over, and only
  // then. They are what a browser with the script blocked still shows, so they
  // stay in the markup - but where the row is doing the work, the browser's own
  // tooltip is the floating box this design removed, arriving a second late
  // over the line it covers. Two answers to one hover, one of them the one that
  // was ruled out.
  //
  const cards = document.querySelectorAll(".traffic-pool");
  if (!cards.length) return;

  const HELD = "traffic-scroll:" + window.location.pathname;
  try {
    const held = sessionStorage.getItem(HELD);
    sessionStorage.removeItem(HELD);
    if (held !== null) window.scrollTo(0, Number(held));
  } catch {
    /* Nothing held, or storage refused. The page opens at the top as before. */
  }

  for (const card of cards) {
    const svg = card.querySelector("svg");
    const row = card.querySelector(".traffic-figures");
    const label = card.querySelector(".traffic-scope-label");
    const note = card.querySelector(".traffic-scope-note");
    const picks = card.querySelectorAll(".traffic-pick");
    if (!svg || !row || !label || !picks.length) continue;

    for (const title of svg.querySelectorAll("title")) title.remove();

    //
    // What the page was rendered with: the window's figures, or a marked
    // range's. A hover is a look at something else and has to be able to put
    // this back exactly, including the coverage marks beside the numbers.
    //
    const values = new Map();
    for (const item of row.querySelectorAll("div")) {
      const name = item.querySelector("dt");
      const value = item.querySelector("dd");
      if (name && value) values.set(name.textContent.trim(), { value, held: value.innerHTML });
    }
    const rendered = label.textContent.trim();

    const show = (pick) => {
      let figures;
      try {
        figures = JSON.parse(pick.dataset.figures || "[]");
      } catch {
        return;
      }
      for (const [name, amount] of figures) {
        const found = values.get(name);
        if (!found) continue;
        found.value.textContent = amount === null ? "—" : String(amount);
      }
      label.textContent = pick.dataset.when || rendered;
      if (note) note.textContent = pick.dataset.note || "";
    };

    const restore = () => {
      for (const { value, held } of values.values()) value.innerHTML = held;
      label.textContent = rendered;
      if (note) note.textContent = "";
    };

    for (const pick of picks) {
      pick.addEventListener("pointerenter", () => show(pick));
      pick.addEventListener("focus", () => show(pick));
      //
      // The mark is painted before the page comes back, so the click has an
      // answer immediately rather than after a round trip. What the server
      // renders is still the authority - this only covers the wait.
      //
      pick.addEventListener("click", () => {
        const rect = pick.querySelector("rect");
        if (rect) rect.classList.add("traffic-picked");
        //
        // Marking a range is a navigation - the marks live in the address, so
        // the browser loads a page and lands at the top of it, with the chart
        // that was just clicked somewhere below the fold. The position is put
        // back on the way in, so the second click leaves the reader looking at
        // the same card as the first.
        //
        try {
          sessionStorage.setItem(HELD, String(window.scrollY));
        } catch {
          /* Storage can be refused outright; the mark still works. */
        }
      });
    }
    svg.addEventListener("pointerleave", restore);
    svg.addEventListener("blur", restore, true);
  }
})();
