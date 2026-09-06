(() => {
  //
  // The traffic card's tooltip.
  //
  // The readings were carried by SVG `<title>`, which is the browser's own
  // tooltip and correct in every way but one: it waits about a second before
  // it appears, and it follows the pointer's idea of a hover rather than the
  // chart's. Reading a line means moving along it, and a tooltip that arrives
  // after the pointer has left is not a tooltip.
  //
  // So the title text is read out of the markup and shown immediately. The
  // `<title>` elements stay where they are: they are what a screen reader and
  // a browser with this script blocked still find, and removing them to avoid
  // showing the same thing twice would trade a small redundancy for a page
  // that answers nothing without script.
  //
  const cards = document.querySelectorAll(".traffic-spark");
  if (!cards.length) return;

  for (const card of cards) {
    const svg = card.querySelector("svg");
    const targets = card.querySelectorAll(".traffic-hit");
    if (!svg || !targets.length) continue;

    //
    // One tip per card rather than one per point: only one can be visible, and
    // a hundred and forty-four detached nodes per pool is a page built for the
    // pointer rather than for the reader.
    //
    const tip = document.createElement("div");
    tip.className = "traffic-tip";
    tip.hidden = true;
    card.appendChild(tip);

    //
    // Suppressed while the tip is up, so the native tooltip does not arrive a
    // second later and sit on top of it. Restored on the way out, which is what
    // keeps the markup's own answer available when this script is not driving.
    //
    let held = null;

    const show = (target) => {
      const title = target.querySelector("title");
      if (!title) return;
      if (held && held !== target) restore();
      tip.textContent = title.textContent;
      tip.hidden = false;

      const box = card.getBoundingClientRect();
      const at = target.getBoundingClientRect();
      const middle = at.left + at.width / 2 - box.left;
      //
      // Clamped to the card, because a point at either end would otherwise
      // push the tip off the edge - and the ends of a window are where a
      // reader looks first.
      //
      const half = tip.offsetWidth / 2;
      const place = Math.min(Math.max(middle, half), box.width - half);
      tip.style.left = `${place}px`;

      held = target;
      target.dataset.title = title.textContent;
      title.remove();
    };

    const restore = () => {
      if (!held) return;
      if (!held.querySelector("title") && held.dataset.title) {
        const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
        title.textContent = held.dataset.title;
        held.appendChild(title);
      }
      held = null;
    };

    const hide = () => {
      tip.hidden = true;
      restore();
    };

    for (const target of targets) {
      target.addEventListener("pointerenter", () => show(target));
      target.addEventListener("focus", () => show(target));
    }
    svg.addEventListener("pointerleave", hide);
    svg.addEventListener("blur", hide, true);
  }
})();
