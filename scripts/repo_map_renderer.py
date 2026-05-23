from __future__ import annotations

import html
from typing import Any
from urllib.parse import quote


REPO_SOURCE_BASE = "https://github.com/duriantaco/skylos"


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _link(path: str, *, label: str | None = None, line: int | None = None) -> str:
    clean = path.rstrip("/")
    route = "tree" if path.endswith("/") else "blob"
    href = f"{REPO_SOURCE_BASE}/{route}/main/{quote(clean, safe='/._-')}"
    if line and route == "blob":
        href = f"{href}#L{line}"
    text = label or clean
    if line:
        text = f"{text}:{line}"
    return (  # skylos: ignore escaped static repo-map HTML
        f'<a href="{_esc(href)}" rel="noopener noreferrer">{_esc(text)}</a>'
    )


def _pill(label: str, value: Any) -> str:
    return (  # skylos: ignore escaped static repo-map HTML
        f'<span class="pill"><strong>{_esc(label)}</strong> {_esc(value)}</span>'
    )


def _persona_attr(item: dict[str, Any]) -> str:
    return _esc(item.get("personas", "user contributor debugger security maintainer"))


def _personas_for(item: dict[str, Any]) -> set[str]:
    return set(str(item.get("personas", "")).split())


def _first_step_for_mode(mode: str, first_steps: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = [item for item in first_steps if mode in _personas_for(item)]
    if not candidates:
        return {
            "title": "Use the full map",
            "time": "10 minutes",
            "steps": [
                "Use search when you already know a path, symbol, or rule id.",
                "Pick a mode when you want unrelated sections hidden.",
                "Start from route cards before opening folder or symbol indexes.",
            ],
            "paths": [],
        }
    return sorted(candidates, key=lambda item: len(_personas_for(item)))[0]


def _mode_plan_template(mode: str, item: dict[str, Any]) -> str:
    steps = "\n".join(f"<li>{_esc(step)}</li>" for step in item["steps"])
    links = " ".join(_link(path) for path in item.get("paths", []))
    link_row = f'<div class="link-row">{links}</div>' if links else ""
    return (  # skylos: ignore escaped static repo-map HTML fragments
        f"""
      <template data-mode-plan="{_esc(mode)}">
        <div class="guide-time">{_esc(item["time"])}</div>
        <h3>{_esc(item["title"])}</h3>
        <ol class="step-list">{steps}</ol>
        {link_row}
      </template>
    """
    )


def render_mode_plan_templates(
    personas: list[dict[str, Any]], first_steps: list[dict[str, Any]]
) -> str:
    """
    Render inert mode-plan templates consumed by docs/repo-map/app.js.

    Args:
        personas: Persona dictionaries with stable ids.
        first_steps: First-step cards tagged with persona ids.

    Returns:
        HTML templates keyed by mode. They are static, escaped, and cloned into
        the visible mode panel when a user chooses a mode.

    Calls: scripts/repo_map_renderer.py _first_step_for_mode;
        scripts/repo_map_renderer.py _mode_plan_template.

    Called from: scripts/repo_map_renderer.py render_mode_selector.
    """
    all_plan = {
        "title": "Use the full map",
        "time": "10 minutes",
        "steps": [
            "Use search when you already know a path, symbol, or rule id.",
            "Pick a mode when you want unrelated sections hidden.",
            "Start from route cards before opening folder or symbol indexes.",
        ],
        "paths": [],
    }
    modes = ["all", *(persona["id"] for persona in personas)]
    return "\n".join(
        _mode_plan_template(
            mode,
            all_plan if mode == "all" else _first_step_for_mode(mode, first_steps),
        )
        for mode in modes
    )


def render_mode_selector(
    personas: list[dict[str, Any]], first_steps: list[dict[str, Any]]
) -> str:
    """
    Render the mode picker plus an immediately visible first-step preview.

    Args:
        personas: Curated mode cards.
        first_steps: First-step cards used to build each mode's preview.

    Returns:
        HTML for the visible current-mode panel, mode cards, and inert
        per-mode templates.

    Calls: scripts/repo_map_renderer.py render_personas;
        scripts/repo_map_renderer.py render_mode_plan_templates.

    Called from: scripts/repo_map_renderer.py render_html.
    """
    return (  # skylos: ignore escaped static repo-map HTML fragments
        f"""
      <div id="mode-panel" class="mode-panel" aria-live="polite">
        <div>
          <div class="mini-label">Current mode</div>
          <h3 id="active-mode-title">Show everything</h3>
          <p id="active-mode-summary">Everything is visible. Choose a mode to hide unrelated cards and rows.</p>
        </div>
        <div>
          <div class="mini-label">First 10 minutes</div>
          <div id="active-mode-plan"></div>
        </div>
      </div>
      <div class="persona-grid">
        {render_personas(personas)}
      </div>
      <div id="mode-plan-templates" hidden>
        {render_mode_plan_templates(personas, first_steps)}
      </div>
    """
    )


def render_personas(personas: list[dict[str, Any]]) -> str:
    """
    Render persona filter cards for the top of the repo map.

    Args:
        personas: Curated persona dictionaries with id, title, summary, search
            text, and paths.

    Returns:
        HTML button cards. Each card carries `data-mode` for client-side
        filtering and escaped search text.

    Calls: scripts/repo_map_renderer.py _esc;
        scripts/repo_map_renderer.py _link.

    Called from: scripts/repo_map_renderer.py render_html.
    """
    cards = [
        """
        <button class="persona-card active" type="button" data-mode="all" data-mode-title="Show everything" data-mode-summary="Everything is visible. Choose a mode to hide unrelated cards and rows." data-search="all everything full map reset" aria-pressed="true">
          <span class="persona-title">Show everything</span>
          <span class="persona-summary">Use this when you already know what you are looking for.</span>
          <span class="link-row"><span class="muted">Full map</span></span>
        </button>
        """
    ]
    for persona in personas:
        links = " ".join(_link(path) for path in persona["paths"])
        search_text = " ".join([persona["title"], persona["summary"], persona.get("search", ""), *persona["paths"]])
        cards.append(
            f"""
            <button class="persona-card searchable" type="button" data-mode="{_esc(persona["id"])}" data-mode-title="{_esc(persona["title"])}" data-mode-summary="{_esc(persona["summary"])}" data-search="{_esc(search_text.lower())}" aria-pressed="false">
              <span class="persona-title">{_esc(persona["title"])}</span>
              <span class="persona-summary">{_esc(persona["summary"])}</span>
              <span class="link-row">{links}</span>
            </button>
            """
        )
    return "\n".join(cards)


def render_workflows(workflows: list[dict[str, Any]]) -> str:
    """
    Render task-oriented route cards.

    Args:
        workflows: Curated workflow dictionaries with title, goal, persona
            tags, paths, tests, and ordered steps.

    Returns:
        HTML article cards showing what to read, what to test, and what action
        to take next.

    Calls: scripts/repo_map_renderer.py _link;
        scripts/repo_map_renderer.py _esc;
        scripts/repo_map_renderer.py _persona_attr.

    Called from: scripts/repo_map_renderer.py render_html.
    """
    cards = []
    for workflow in workflows:
        path_links = " ".join(_link(path) for path in workflow["paths"])
        test_links = " ".join(_link(path) for path in workflow["tests"])
        steps = "\n".join(f"<li>{_esc(step)}</li>" for step in workflow.get("steps", []))
        search_text = " ".join(
            [workflow["title"], workflow["goal"], *workflow["paths"], *workflow["tests"], *workflow.get("steps", [])]
        )
        cards.append(
            f"""
            <article class="route-card searchable persona-target" data-personas="{_persona_attr(workflow)}" data-search="{_esc(search_text.lower())}">
              <h3>{_esc(workflow["title"])}</h3>
              <p>{_esc(workflow["goal"])}</p>
              <ol class="step-list">{steps}</ol>
              <div class="mini-label">Start with</div>
              <div class="link-row">{path_links}</div>
              <div class="mini-label">Tests / proof</div>
              <div class="link-row">{test_links}</div>
            </article>
            """
        )
    return "\n".join(cards)


def render_first_steps(first_steps: list[dict[str, Any]]) -> str:
    cards = []
    for item in first_steps:
        steps = "\n".join(f"<li>{_esc(step)}</li>" for step in item["steps"])
        links = " ".join(_link(path) for path in item["paths"])
        search_text = " ".join([item["title"], item["time"], *item["steps"], *item["paths"]])
        cards.append(
            f"""
            <article class="guide-card searchable persona-target" data-personas="{_persona_attr(item)}" data-search="{_esc(search_text.lower())}">
              <div class="guide-time">{_esc(item["time"])}</div>
              <h3>{_esc(item["title"])}</h3>
              <ol class="step-list">{steps}</ol>
              <div class="link-row">{links}</div>
            </article>
            """
        )
    return "\n".join(cards)


def render_sharp_edges(groups: list[dict[str, Any]]) -> str:
    cards = []
    for group in groups:
        items = "\n".join(f"<li>{_esc(item)}</li>" for item in group["items"])
        search_text = " ".join([group["title"], *group["items"]])
        cards.append(
            f"""
            <article class="guide-card searchable" data-search="{_esc(search_text.lower())}">
              <h3>{_esc(group["title"])}</h3>
              <ul>{items}</ul>
            </article>
            """
        )
    return "\n".join(cards)


def render_architecture_layers(layers: list[dict[str, Any]]) -> str:
    """
    Render the architecture-at-a-glance section.

    Args:
        layers: Curated layer dictionaries with purpose, dependency direction,
            guardrail, persona tags, and representative paths.

    Returns:
        HTML cards that explain ownership boundaries before users open files.

    Invariants:
        Keep this conceptual and small. The page should guide navigation, not
        become a giant dependency graph.

    Calls: scripts/repo_map_renderer.py _link;
        scripts/repo_map_renderer.py _esc;
        scripts/repo_map_renderer.py _persona_attr.

    Called from: scripts/repo_map_renderer.py render_html.
    """
    cards = []
    for layer in layers:
        links = " ".join(_link(path) for path in layer["paths"])
        search_text = " ".join(
            [
                layer["title"],
                layer["purpose"],
                layer["depends_on"],
                layer["guardrail"],
                *layer["paths"],
            ]
        )
        cards.append(
            f"""
            <article class="arch-card searchable persona-target" data-personas="{_persona_attr(layer)}" data-search="{_esc(search_text.lower())}">
              <h3>{_esc(layer["title"])}</h3>
              <p>{_esc(layer["purpose"])}</p>
              <div class="mini-label">Depends on</div>
              <p class="compact">{_esc(layer["depends_on"])}</p>
              <div class="mini-label">Guardrail</div>
              <p class="compact">{_esc(layer["guardrail"])}</p>
              <div class="link-row">{links}</div>
            </article>
            """
        )
    return "\n".join(cards)


def render_docstring_guide(items: list[dict[str, str]]) -> str:
    """
    Render the guidance for future key-function docstrings.

    Args:
        items: Curated docstring guidance items with title and body text.

    Returns:
        HTML cards describing what maintainers should document for important
        functions and classes.

    Called from: scripts/repo_map_renderer.py render_html.
    """
    cards = []
    for item in items:
        search_text = f"{item['title']} {item['body']}"
        cards.append(
            f"""
            <article class="doc-card searchable persona-target" data-personas="contributor debugger security maintainer" data-search="{_esc(search_text.lower())}">
              <h3>{_esc(item["title"])}</h3>
              <p>{_esc(item["body"])}</p>
            </article>
            """
        )
    return "\n".join(cards)


def render_flow() -> str:
    """
    Render the main scan-flow pipeline.

    Args:
        None.

    Returns:
        HTML cards for the fixed high-level flow from input to output.

    Called from: scripts/repo_map_renderer.py render_flow_section.
    """
    steps = [
        ("Input", "CLI args, changed files, config", ["skylos/cli.py", "skylos/config.py"]),
        ("Discovery", "Select source files and language paths", ["skylos/discover/", "skylos/pipeline.py"]),
        ("Analysis", "Static detectors, rules, liveness, evidence", ["skylos/analyzer.py", "skylos/rules/", "skylos/analysis/"]),
        ("Review", "LLM/agent review and evidence grounding where enabled", ["skylos/llm/", "skylos/agents/", "skylos/adapters/"]),
        ("Output", "Pretty output, SARIF, cloud upload, CI review", ["skylos/reporting/", "skylos/cloud/", "skylos/cicd/"]),
    ]
    rendered = []
    for label, detail, paths in steps:
        links = " ".join(_link(path) for path in paths)
        search_text = f"{label} {detail} {' '.join(paths)}"
        rendered.append(
            f"""
            <div class="flow-step searchable" data-search="{_esc(search_text.lower())}">
              <div class="flow-title">{_esc(label)}</div>
              <p>{_esc(detail)}</p>
              <div class="link-row">{links}</div>
            </div>
            """
        )
    return "\n".join(rendered)


def render_folder_cards(cards: list[dict[str, Any]]) -> str:
    """
    Render all folder ownership cards.

    Args:
        cards: Folder card dictionaries produced by collect_repo_map.

    Returns:
        Concatenated HTML for each folder card.

    Calls: scripts/repo_map_renderer.py render_folder_card.

    Called from: scripts/repo_map_renderer.py render_folder_section.
    """
    return "\n".join(render_folder_card(card) for card in cards)


def render_folder_card(card: dict[str, Any]) -> str:
    """
    Render one folder ownership card.

    Args:
        card: Folder metadata and generated facts. Expected keys include path,
            purpose, touch, entrypoints, tests, modules, and key_symbols.

    Returns:
        HTML article with folder purpose, touch guidance, entrypoints, nearby
        tests, important files, and key symbols.

    Calls: scripts/repo_map_renderer.py _link;
        scripts/repo_map_renderer.py _pill;
        scripts/repo_map_renderer.py _folder_detail_lists;
        scripts/repo_map_renderer.py _folder_search_text.

    Called from: scripts/repo_map_renderer.py render_folder_cards.
    """
    modules = "\n".join(
        f"<li>{_link(module.path)} <span>{_esc(module.lines)} lines</span></li>"
        for module in card["modules"]
    )
    symbols = "\n".join(
        f"<li>{_link(item['path'], label=item['name'], line=item['line'])} <span>{_esc(item['kind'])}</span></li>"
        for item in card["key_symbols"]
    )
    entrypoints = " ".join(_link(path) for path in card["entrypoints"]) or '<span class="muted">Generated only</span>'
    tests = " ".join(_link(path) for path in card["tests"]) or '<span class="muted">No obvious matching test file</span>'
    return (  # skylos: ignore escaped static repo-map HTML fragments
        f"""
    <article class="folder-card searchable" data-search="{_esc(_folder_search_text(card))}">
      <div class="card-head">
        <h3>{_link(card["path"])}</h3>
        <div class="stat-row">
          {_pill("files", card["files"])}
          {_pill("symbols", card["symbols"])}
          {_pill("lines", card["lines"])}
        </div>
      </div>
      <p>{_esc(card["purpose"])}</p>
      <p class="touch"><strong>Touch when:</strong> {_esc(card["touch"])}</p>
      <details>
        <summary>Entrypoints, tests, and key symbols</summary>
        <div class="mini-label">Entrypoints</div>
        <div class="link-row">{entrypoints}</div>
        <div class="mini-label">Nearby tests</div>
        <div class="link-row">{tests}</div>
        <div class="split-list">{_folder_detail_lists(modules, symbols)}</div>
      </details>
    </article>
    """
    )


def _folder_search_text(card: dict[str, Any]) -> str:
    return " ".join(
        [
            card["path"],
            card["purpose"],
            card["touch"],
            " ".join(card["entrypoints"]),
            " ".join(card["tests"]),
            " ".join(module.path for module in card["modules"]),
        ]
    ).lower()


def _folder_detail_lists(modules: str, symbols: str) -> str:
    symbol_rows = symbols or '<li><span class="muted">No top-level symbols</span></li>'
    return (  # skylos: ignore escaped static repo-map HTML fragments
        f"""
      <div>
        <div class="mini-label">Important files</div>
        <ul>{modules}</ul>
      </div>
      <div>
        <div class="mini-label">Key symbols</div>
        <ul>{symbol_rows}</ul>
      </div>
    """
    )


def render_hot_modules(modules: list[Any]) -> str:
    """
    Render high-risk or high-traffic modules.

    Args:
        modules: ModuleInfo-like objects sorted by size and symbol count.

    Returns:
        Table rows with path, line count, public/all symbol count, risk labels,
        and summary.

    Calls: scripts/repo_map_renderer.py _hot_module_labels;
        scripts/repo_map_renderer.py _link;
        scripts/repo_map_renderer.py _esc.

    Called from: scripts/repo_map_renderer.py render_hot_section.
    """
    rows = []
    for module in modules:
        public_symbols = sum(1 for symbol in module.symbols if not symbol.private)
        labels = _hot_module_labels(module)
        label_html = " ".join(f'<span class="warn">{_esc(label)}</span>' for label in labels) or '<span class="muted">watch</span>'
        rows.append(
            f"""
            <tr class="searchable" data-search="{_esc((module.path + " " + module.summary).lower())}">
              <td>{_link(module.path)}</td>
              <td>{_esc(module.lines)}</td>
              <td>{_esc(public_symbols)} / {_esc(len(module.symbols))}</td>
              <td>{label_html}</td>
              <td>{_esc(module.summary)}</td>
            </tr>
            """.rstrip()
        )
    return "\n".join(rows)


def _hot_module_labels(module: Any) -> list[str]:
    labels = []
    if module.lines >= 600:
        labels.append("large")
    if len(module.symbols) >= 40:
        labels.append("many symbols")
    if module.path in {"skylos/cli.py", "skylos/analyzer.py", "skylos/pipeline.py", "skylos/config.py"}:
        labels.append("shared path")
    return labels


def render_symbol_index(symbols: list[dict[str, Any]]) -> str:
    """
    Render the searchable symbol index.

    Args:
        symbols: Bounded symbol dictionaries from collect_repo_map.

    Returns:
        HTML table rows for symbol name, kind, surface, and file path.

    Called from: scripts/repo_map_renderer.py render_symbol_section.
    """
    rows = []
    for item in symbols:
        badge = '<span class="muted">private</span>' if item["private"] else '<span class="ok">public</span>'
        search_text = " ".join([item["name"], item["kind"], item["path"], item["summary"]])
        rows.append(
            f"""
            <tr class="searchable" data-search="{_esc(search_text.lower())}">
              <td>{_link(item["path"], label=item["name"], line=item["line"])}</td>
              <td>{_esc(item["kind"])}</td>
              <td>{badge}</td>
              <td>{_esc(item["path"])}</td>
            </tr>
            """.rstrip()
        )
    return "\n".join(rows)


def render_glossary(items: list[tuple[str, str]]) -> str:
    return "\n".join(
        f"""
        <div class="term searchable" data-search="{_esc((term + " " + meaning).lower())}">
          <dt>{_esc(term)}</dt>
          <dd>{_esc(meaning)}</dd>
        </div>
        """
        for term, meaning in items
    )


def render_html(data: dict[str, Any]) -> str:
    """
    Render the full repo-map HTML document.

    Args:
        data: Deterministic map data from scripts/build_repo_map.py
            collect_repo_map.

    Returns:
        Full HTML page string. CSS and JS are external files under
        docs/repo-map/.

    Trust boundary:
        Dynamic values come from repository metadata and are escaped by the
        lower-level render helpers before interpolation.

    Calls: scripts/repo_map_renderer.py render_snapshot;
        scripts/repo_map_renderer.py section;
        scripts/repo_map_renderer.py render_flow_section;
        scripts/repo_map_renderer.py render_folder_section;
        scripts/repo_map_renderer.py render_hot_section;
        scripts/repo_map_renderer.py render_symbol_section.

    Called from: scripts/build_repo_map.py write_repo_map;
        scripts/build_repo_map.py main.
    """
    sections = [
        render_snapshot(data),
        section(
            "personas",
            "Choose A Mode",
            render_mode_selector(data["personas"], data["first_steps"]),
            PERSONA_COPY,
            "mode-stack",
        ),
        section("first-steps", "First 10 Minutes", render_first_steps(data["first_steps"]), FIRST_STEPS_COPY),
        section("routes", "Start Here", render_workflows(data["workflows"])),
        section("sharp-edges", "Safe Path", render_sharp_edges(data["sharp_edges"]), SAFE_PATH_COPY),
        section("architecture", "Architecture", render_architecture_layers(data["architecture_layers"]), ARCHITECTURE_COPY, "arch-grid"),
        section("docstrings", "Docstring Standard", render_docstring_guide(data["docstring_guide"]), DOCSTRING_COPY, "doc-grid"),
        render_flow_section(),
        render_folder_section(data),
        render_hot_section(data),
        render_symbol_section(data),
        section("terms", "Vocabulary", f"<dl>{render_glossary(data['glossary'])}</dl>"),
    ]
    return PAGE_TEMPLATE.format(sections="\n".join(sections))


def render_snapshot(data: dict[str, Any]) -> str:
    """
    Render repository-level counts and the comprehension-debt framing note.

    Args:
        data: Full map data dictionary.

    Returns:
        HTML section for top-level metrics and context.

    Called from: scripts/repo_map_renderer.py render_html.
    """
    guided_routes = len(data["workflows"]) + len(data["first_steps"])
    return (  # skylos: ignore escaped static repo-map HTML fragments
        f"""
    <section>
      <h2>Repo Snapshot</h2>
      <p class="lede">Use the route cards first. The folder and symbol sections are there when you need detail.</p>
      <div class="meta-grid">
        <div class="metric"><strong>{_esc(data["python_file_count"])}</strong><span>Python files scanned</span></div>
        <div class="metric"><strong>{_esc(data["symbol_count"])}</strong><span>top-level classes/functions</span></div>
        <div class="metric"><strong>{_esc(len(data["folder_cards"]))}</strong><span>ownership areas</span></div>
        <div class="metric"><strong>{_esc(guided_routes)}</strong><span>guided routes</span></div>
      </div>
      <div class="note">{COMPREHENSION_COPY}</div>
    </section>
    """
    )


def section(section_id: str, title: str, body: str, lede: str = "", grid_class: str | None = None) -> str:
    """
    Wrap rendered cards in a named page section.

    Args:
        section_id: HTML id and sidebar anchor target.
        title: Section heading text.
        body: Already-rendered safe HTML card content.
        lede: Optional introductory sentence.
        grid_class: Optional CSS grid class override.

    Returns:
        HTML section wrapper.

    Called from: scripts/repo_map_renderer.py render_html.
    """
    lede_html = f'<p class="lede">{_esc(lede)}</p>' if lede else ""
    resolved_grid = grid_class or ("guide-grid" if section_id in {"first-steps", "sharp-edges"} else "route-grid")
    return (  # skylos: ignore escaped static repo-map HTML fragments
        f"""
    <section id="{_esc(section_id)}">
      <h2>{_esc(title)}</h2>
      {lede_html}
      <div class="{_esc(resolved_grid)}">
        {body}
      </div>
    </section>
    """
    )


def render_flow_section() -> str:
    return (  # skylos: ignore escaped static repo-map HTML fragments
        f"""
    <section id="flow">
      <h2>Scan Flow</h2>
      <div class="flow">{render_flow()}</div>
    </section>
    """
    )


def render_folder_section(data: dict[str, Any]) -> str:
    return (  # skylos: ignore escaped static repo-map HTML fragments
        f"""
    <section id="folders">
      <h2>Folders</h2>
      <div class="folder-grid">{render_folder_cards(data["folder_cards"])}</div>
    </section>
    """
    )


def render_hot_section(data: dict[str, Any]) -> str:
    return (  # skylos: ignore escaped static repo-map HTML fragments
        f"""
    <section id="hot">
      <h2>Hot Zones</h2>
      <p class="lede">These files are not bad by default. They are places where a small change can affect many workflows.</p>
      <table>
        <thead><tr><th>File</th><th>Lines</th><th>Public / all symbols</th><th>Signal</th><th>What it seems to own</th></tr></thead>
        <tbody>{render_hot_modules(data["hot_modules"])}</tbody>
      </table>
    </section>
    """
    )


def render_symbol_section(data: dict[str, Any]) -> str:
    return (  # skylos: ignore escaped static repo-map HTML fragments
        f"""
    <section id="symbols">
      <h2>Symbol Index</h2>
      <p class="lede">Search is the intended interface here. The page keeps private helper symbols mostly hidden except in shared core files.</p>
      <table>
        <thead><tr><th>Symbol</th><th>Kind</th><th>Surface</th><th>File</th></tr></thead>
        <tbody>{render_symbol_index(data["symbol_index"])}</tbody>
      </table>
    </section>
    """
    )


FIRST_STEPS_COPY = "Pick the card that matches your situation. Stop after the listed files unless you have a reason to go deeper."
PERSONA_COPY = "Choose the closest job-to-be-done. The page will hide unrelated cards while keeping search available."
SAFE_PATH_COPY = "This is the quick judgment layer: where a new contributor can start, where to slow down, and what proof usually matters."
ARCHITECTURE_COPY = "Use this when a change crosses ownership boundaries. It shows dependency direction and the guardrail for each layer."
DOCSTRING_COPY = "Use these fields for key functions, not every helper. The goal is to preserve editing judgment, trust boundaries, and proof expectations."
COMPREHENSION_COPY = (
    "Comprehension debt grows when the codebase changes faster than the team can maintain a shared mental model. "
    'This page keeps the first question simple: where should I start? Source framing: '
    '<a href="https://dev.to/javz/your-codebase-has-technical-debt-but-does-your-team-have-comprehension-debt-385f">'
    "DEV Community article</a>."
)

PAGE_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Skylos Repo Map</title>
  <link rel="stylesheet" href="./styles.css">
</head>
<body>
  <div class="shell">
    <aside>
      <h1>Skylos Map</h1>
      <p class="lede">A generated repo navigator for building a mental model before opening random files.</p>
      <div class="search-box">
        <label class="mini-label" for="repo-search">Search paths, symbols, concepts</label>
        <input id="repo-search" type="search" placeholder="Try: LLM, config, false positive, SKY-SC001">
      </div>
      <nav>
        <a href="#routes">Start Here</a>
        <a href="#personas">Choose A Mode</a>
        <a href="#first-steps">First 10 Minutes</a>
        <a href="#sharp-edges">Safe Path</a>
        <a href="#architecture">Architecture</a>
        <a href="#docstrings">Docstrings</a>
        <a href="#flow">Scan Flow</a>
        <a href="#folders">Folders</a>
        <a href="#hot">Hot Zones</a>
        <a href="#symbols">Symbol Index</a>
        <a href="#terms">Vocabulary</a>
      </nav>
      <div class="note">
        Generated by <code>scripts/build_repo_map.py</code>. Edit the generator, not this HTML.
      </div>
    </aside>
    <main>
      {sections}
      <div id="empty-state" class="empty-state">No matching cards or rows. Try a folder, symbol, rule type, or workflow name.</div>
    </main>
  </div>
  <script src="./app.js"></script>
</body>
</html>
"""
