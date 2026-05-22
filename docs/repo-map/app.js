const search = document.getElementById("repo-search");
const emptyState = document.getElementById("empty-state");
const items = Array.from(document.querySelectorAll(".searchable"));

function applySearch() {
  const tokens = search.value.toLowerCase().trim().split(/\s+/).filter(Boolean);
  let visible = 0;

  for (const item of items) {
    const haystack = item.dataset.search || "";
    const matched = tokens.length === 0 || tokens.every((token) => haystack.includes(token));
    item.hidden = !matched;
    if (matched) {
      visible += 1;
    }
  }

  emptyState.style.display = visible === 0 ? "block" : "none";
}

search.addEventListener("input", applySearch);
