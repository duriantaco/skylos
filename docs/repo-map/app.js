const search = document.getElementById("repo-search");
const emptyState = document.getElementById("empty-state");
const items = Array.from(document.querySelectorAll(".searchable"));
const personaButtons = Array.from(document.querySelectorAll(".persona-card[data-mode]"));
const modePanel = document.getElementById("mode-panel");
const activeModeTitle = document.getElementById("active-mode-title");
const activeModeSummary = document.getElementById("active-mode-summary");
const activeModePlan = document.getElementById("active-mode-plan");
const modePlanTemplates = new Map(
  Array.from(document.querySelectorAll("template[data-mode-plan]")).map((template) => [
    template.dataset.modePlan,
    template,
  ]),
);
let activeMode = "all";

function updateModePanel(button, { animate = false } = {}) {
  activeModeTitle.textContent = button.dataset.modeTitle || button.textContent.trim();
  activeModeSummary.textContent = button.dataset.modeSummary || "";

  const template = modePlanTemplates.get(activeMode) || modePlanTemplates.get("all");
  activeModePlan.replaceChildren();
  if (template) {
    activeModePlan.appendChild(template.content.cloneNode(true));
  }

  if (animate && modePanel) {
    modePanel.classList.remove("mode-panel-updated");
    window.requestAnimationFrame(() => modePanel.classList.add("mode-panel-updated"));
  }
}

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
      option.setAttribute("aria-pressed", option === button ? "true" : "false");
    }
    updateModePanel(button, { animate: true });
    applySearch();
  });
}

const initialMode = personaButtons.find((button) => button.classList.contains("active")) || personaButtons[0];
if (initialMode) {
  updateModePanel(initialMode);
}
