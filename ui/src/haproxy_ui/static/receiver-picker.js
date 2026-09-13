(() => {
  const options = Array.from(document.querySelectorAll("[data-receiver-option]"));
  if (!options.length) return;

  const count = document.querySelector("[data-receiver-count]");
  const search = document.querySelector("[data-receiver-search]");
  const empty = document.querySelector("[data-receiver-empty]");

  const updateCount = () => {
    if (!count) return;
    const selected = options.filter((option) => option.querySelector("input").checked).length;
    count.textContent = `${selected} selected`;
  };

  options.forEach((option) => option.querySelector("input").addEventListener("change", updateCount));
  updateCount();

  if (!search) return;
  search.hidden = false;
  const input = search.querySelector("input");
  input.addEventListener("input", () => {
    const query = input.value.trim().toLocaleLowerCase();
    let visible = 0;
    options.forEach((option) => {
      const matches = option.textContent.toLocaleLowerCase().includes(query);
      option.hidden = !matches;
      if (matches) visible += 1;
    });
    if (empty) empty.hidden = visible !== 0;
  });
})();
