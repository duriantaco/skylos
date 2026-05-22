const search = document.getElementById("repo-search");
const emptyState = document.getElementById("empty-state");
const items = Array.from(document.querySelectorAll(".searchable"));
const personaButtons = Array.from(document.querySelectorAll(".persona-card[data-mode]"));
let activeMode = "all";

function applySearch() {
  const tokens = search.value.toLowerCase().trim().split(/\s+/).filter(Boolean);
  let visible = 0;

  for (const item of items) {
    const haystack = item.dataset.search || "";
    const searchMatched = tokens.length === 0 || tokens.every((token) => haystack.includes(token));
    const personas = item.dataset.personas || "";
    const modeMatched = activeMode === "all" || !personas || personas.split(/\s+/).includes(activeMode);
    const matched = searchMatched && modeMatched;
    item.hidden = !matched;
    if (matched) {
      visible += 1;
    }
  }

  emptyState.style.display = visible === 0 ? "block" : "none";
}

search.addEventListener("input", applySearch);

for (const button of personaButtons) {
  button.addEventListener("click", () => {
    activeMode = button.dataset.mode || "all";
    for (const option of personaButtons) {
      option.classList.toggle("active", option === button);
    }
    applySearch();
  });
}
