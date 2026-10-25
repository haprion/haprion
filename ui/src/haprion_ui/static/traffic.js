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
  // stay in the markup - but where the row is doing the work, the browser's
  // own tooltip is the floating box this design removed, arriving a second
  // late over the line it covers.
  //
  const REGION = "[data-traffic-region]";

  const wire = (root) => {
    for (const card of root.querySelectorAll(".traffic-card")) {
      //
      // Once per card: the page's own swap and live.js's redraw both bring
      // new cards, and a card wired twice would answer each hover twice.
      //
      if (card.dataset.wired) continue;
      card.dataset.wired = "true";
      const svg = card.querySelector("svg");
      const row = card.querySelector(".traffic-figures");
      const label = card.querySelector(".traffic-scope-label");
      const note = card.querySelector(".traffic-scope-note");
      const picks = card.querySelectorAll(".traffic-pick");
      if (!svg || !row || !label) continue;

      for (const title of svg.querySelectorAll("title")) title.remove();

      //
      // What the page was rendered with: the window's figures, or a marked
      // range's. A hover is a look at something else and has to be able to put
      // this back exactly.
      //
      const values = new Map();
      for (const item of row.querySelectorAll("div")) {
        const name = item.querySelector("dt");
        const value = item.querySelector("dd");
        if (name && value) values.set(name.textContent.trim(), { value, held: value.innerHTML });
      }
      const rendered = label.textContent.trim();

      const show = (pick) => {
        //
        // A bucket inside the marked range answers with the range's own
        // figures, which are the ones already on the card. The reader marked
        // a stretch to ask about the stretch; replacing the answer with one
        // bucket's numbers the moment the pointer crosses the band takes the
        // answer away exactly where it is being read.
        //
        // Once both ends are marked, every bucket answers so (2026-10-05):
        // the range stays on the card until the next click or `clear`, and a
        // pointer resting on the line beside the band does not replace it.
        //
        const marks = new URLSearchParams(window.location.search);
        if (pick.dataset.selected || (marks.has("from") && marks.has("to"))) {
          restore();
          return;
        }
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
      }
      svg.addEventListener("pointerleave", restore);
      svg.addEventListener("blur", restore, true);

      //
      // A figure that says its own piece: a total large enough to be printed
      // short. It answers in the note row, where every other reading on this
      // card answers.
      //
      // Listened for on the row, not on each figure: `restore` writes the
      // figures back as markup, which makes new elements - and a listener on
      // the old element was gone after the first look at the line (2026-10-05).
      //
      row.addEventListener("pointerover", (event) => {
        const said = event.target.closest("[data-note]");
        if (said && note) note.textContent = said.dataset.note || "";
      });
      row.addEventListener("pointerout", (event) => {
        const said = event.target.closest("[data-note]");
        if (said && !said.contains(event.relatedTarget)) restore();
      });
    }
  };

  //
  // Marking, and clearing, without reloading the page around the chart.
  //
  // The marks live in the address - that is what makes a range something you
  // can paste to somebody mid-incident - so every click here is a navigation,
  // and a navigation redraws the whole page and throws the reader back to the
  // top of it. Three clicks to measure a stretch meant three of those.
  //
  // So the click is answered by fetching the very same address and swapping
  // in the traffic regions the server rendered for it. The server still does
  // every sum: the figures come from `read_backend_totals` exactly as they do on
  // a full load, and nothing here recomputes them - a second implementation of
  // that arithmetic in the browser is a second answer that can drift.
  //
  // Without this script the links are plain links and behave as they always
  // did, which is the reason the marks are links in the first place.
  //
  //
  // `href` off an SVG `<a>` is an `SVGAnimatedString`, not a string - the
  // bucket links live inside the drawing, so reading the property produced
  // "[object SVGAnimatedString]" and navigated to it. The attribute is the
  // same text on both kinds of link, so it is what is read.
  //
  const address = (link) => link.getAttribute("href");

  const swap = async (href, push) => {
    const answer = await fetch(href, { credentials: "same-origin" });
    if (!answer.ok) throw new Error(String(answer.status));
    const parsed = new DOMParser().parseFromString(await answer.text(), "text/html");
    const fresh = parsed.querySelectorAll(REGION);
    const here = document.querySelectorAll(REGION);
    //
    // Refused rather than patched up. A page whose regions no longer line up
    // is a different page - a session that expired into a login form, or a
    // cluster that has gone - and half-replacing it would leave the reader
    // looking at two answers at once.
    //
    if (!fresh.length || fresh.length !== here.length) throw new Error("shape");
    here.forEach((region, index) => region.replaceWith(fresh[index]));
    const freshRanges = parsed.querySelector(".page-ranges-sticky");
    const hereRanges = document.querySelector(".page-ranges-sticky");
    if (freshRanges && hereRanges) hereRanges.replaceWith(freshRanges);
    if (push) history.pushState({ traffic: true }, "", href);
    wire(document);
  };

  const follow = (href) => {
    swap(href, true).catch(() => {
      //
      // Anything unexpected - offline, a redirect to a login page, a shape
      // that no longer matches - falls back to the navigation this replaced.
      //
      window.location.href = href;
    });
  };

  document.addEventListener("click", (event) => {
    if (event.button !== 0 || event.defaultPrevented) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;

    const pick = event.target.closest(".traffic-pick, .traffic-clear, .page-ranges a");
    if (pick) {
      event.preventDefault();
      follow(address(pick));
      return;
    }

    //
    // The third click clears the marked range, wherever it lands. It already
    // did inside the drawing - the link under every bucket carries "clear both
    // marks" once both are set - but a reader who has finished with a range
    // clicks it away somewhere in the page, not on a bucket.
    //
    // Only while a range is marked, because that is the only state this can
    // undo, and never over a link, a control, or a selection somebody is
    // making with the pointer: those already mean something.
    //
    const clear = document.querySelector(".traffic-clear");
    if (!clear) return;
    if (event.target.closest("a, button, input, select, textarea, summary, label, [role]")) return;
    if (String(window.getSelection() || "")) return;
    event.preventDefault();
    follow(address(clear));
  });

  //
  // The back button walks the marks back, which is the whole reason they are
  // in the address. Answered the same way as a click, so going back is as
  // still as going forward.
  //
  window.addEventListener("popstate", () => {
    swap(window.location.href, false).catch(() => window.location.reload());
  });

  //
  // live.js redraws <main> in place, cards and all (review 26-10-24, 04-07):
  // without this the hover stopped writing into the row and the browser's own
  // tooltips came back.
  //
  document.addEventListener("haprion:redrawn", () => wire(document));

  wire(document);
})();
