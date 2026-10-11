(() => {
  "use strict";

  // Rows per page on a page the server pages (Events -> Audit): choosing a size
  // asks for the first page at that size, with the filters it belongs to.
  document.addEventListener("change", (event) => {
    const select = event.target.closest?.("select[data-page-size]");
    if (select?.form) select.form.requestSubmit();
  });
})();
