(() => {
  // Proxies belong to a block token only, the cluster boxes to "Only these",
  // and a proxy is offered only in a cluster the token may see. What is
  // hidden is disabled too, so it cannot be posted by mistake. Without script
  // every field stays, and the server refuses what does not fit.
  const levels = Array.from(document.querySelectorAll("input[data-level]"));
  const scopes = Array.from(document.querySelectorAll("input[data-cluster-scope]"));
  const clusters = Array.from(document.querySelectorAll("input[data-cluster]"));
  const show = (element, shown) => {
    element.hidden = !shown;
    element.querySelectorAll("input").forEach((input) => { input.disabled = !shown; });
  };
  const sync = () => {
    const level = levels.find((input) => input.checked);
    const scope = scopes.find((input) => input.checked);
    const all = !scope || scope.value === "all";
    const seen = new Set(clusters.filter((input) => input.checked).map((input) => input.value));
    document.querySelectorAll("[data-for-level]").forEach((field) => {
      show(field, Boolean(level) && level.value === field.dataset.forLevel);
    });
    document.querySelectorAll("[data-for-scope]").forEach((box) => show(box, !all));
    document.querySelectorAll("[data-in-clusters]").forEach((box) => {
      const inside = box.dataset.inClusters.split(" ").some((name) => seen.has(name));
      const field = box.closest("[data-for-level]");
      box.hidden = !(all || inside);
      box.querySelector("input").disabled = box.hidden || (field && field.hidden);
    });
  };
  [...levels, ...scopes, ...clusters].forEach((input) => input.addEventListener("change", sync));
  sync();
})();
