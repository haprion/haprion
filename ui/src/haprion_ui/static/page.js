(() => {
  //
  // What the markup asks for by attribute rather than by inline style or
  // inline script, which the page's Content-Security-Policy refuses (review
  // 26-10-13, S2). Style set through the DOM is not inline style, so a
  // position computed on the server travels as a number and is put in place
  // here.
  //
  // data-top / data-left: a percentage, as the traffic card's scale and axis
  // use it. Applied on load and to whatever a redraw swaps in.
  //
  const SIDES = [
    ["top", "top"],
    ["left", "left"],
  ];

  const place = (root) => {
    SIDES.forEach(([key, side]) => {
      const marked = root.matches && root.matches(`[data-${key}]`) ? [root] : [];
      marked.concat(Array.from(root.querySelectorAll(`[data-${key}]`))).forEach((element) => {
        const share = Number.parseFloat(element.dataset[key]);
        if (Number.isFinite(share)) element.style[side] = `${share}%`;
      });
    });
  };

  //
  // data-submit-on-change: a select that submits its form when chosen, as a
  // filter or a provider list does. Delegated, so a redrawn form keeps it.
  //
  document.addEventListener("change", (event) => {
    const field = event.target;
    if (field instanceof HTMLSelectElement && field.hasAttribute("data-submit-on-change") && field.form) {
      field.form.submit();
    }
  });

  window.addEventListener("DOMContentLoaded", () => {
    place(document);
    new MutationObserver((changes) => {
      changes.forEach((change) => {
        change.addedNodes.forEach((node) => {
          if (node instanceof Element) place(node);
        });
      });
    }).observe(document.body, { childList: true, subtree: true });
  });
})();
