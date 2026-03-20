import "./styles.css";

type Summary = {
  headline?: string;
  subtitle?: string;
  new_findings?: number;
  changed_file_count?: number;
  dismissed?: number;
  snoozed?: number;
};

type Finding = {
  fingerprint: string;
  message: string;
  file: string;
  absolute_file?: string;
  line: number;
};

type Action = {
  id: string;
  title: string;
  subtitle?: string;
  file: string;
  absolute_file?: string;
  line: number;
  severity: string;
  reason?: string;
};

type TriageEntry = {
  status: string;
  updated_at?: string;
  snoozed_until?: string;
};

type AgentState = {
  generated_at?: string;
  summary?: Summary;
  actions?: Action[];
  findings?: Finding[];
  triage?: Record<string, TriageEntry>;
};

type ServiceStatus = {
  running: boolean;
  url?: string | null;
  token?: string | null;
};

type TraySnapshot = {
  headline?: string;
  subtitle?: string;
  activeCount?: number;
  newCount?: number;
  changedCount?: number;
  triagedCount?: number;
  topActionTitle?: string;
  topActionPath?: string;
  topActionLine?: number;
};

type Settings = {
  repoPath: string;
  binary: string;
  host: string;
  port: number;
  token: string;
  limit: number;
  refreshOnStart: boolean;
};

const STORAGE_KEY = "skylos-companion-settings";
const POLL_MS = 7000;
const REFRESH_EVENT = "skylos://refresh";

const defaults: Settings = {
  repoPath: "",
  binary: "skylos",
  host: "127.0.0.1",
  port: 5089,
  token: "",
  limit: 10,
  refreshOnStart: true,
};

const elements = {
  headline: byId("headline"),
  subtitle: byId("subtitle"),
  connectionChip: byId("connection-chip"),
  runtimeChip: byId("runtime-chip"),
  updatedAt: byId("updated-at"),
  activeCount: byId("active-count"),
  newCount: byId("new-count"),
  changedCount: byId("changed-count"),
  triagedCount: byId("triaged-count"),
  activeQueue: byId("active-queue"),
  triagedList: byId("triaged-list"),
  saveSettings: byId("save-settings"),
  startService: byId("start-service"),
  stopService: byId("stop-service"),
  refreshState: byId("refresh-state"),
  serviceNote: byId("service-note"),
  repoPath: byId("repo-path") as HTMLInputElement,
  binary: byId("service-binary") as HTMLInputElement,
  host: byId("service-host") as HTMLInputElement,
  port: byId("service-port") as HTMLInputElement,
  token: byId("service-token") as HTMLInputElement,
  limit: byId("action-limit") as HTMLInputElement,
  refreshOnStart: byId("refresh-on-start") as HTMLInputElement,
};

let state: AgentState | null = null;
let pollingHandle: number | undefined;
let invokeFn: ((command: string, args?: Record<string, unknown>) => Promise<unknown>) | null = null;

bootstrap().catch((error) => {
  renderError(`Bootstrap failed: ${error instanceof Error ? error.message : String(error)}`);
});

async function bootstrap(): Promise<void> {
  hydrateSettings();
  bindControls();
  await bindRuntimeEvents();
  elements.runtimeChip.textContent = isTauriRuntime() ? "Tauri runtime" : "Browser preview";
  await updateManagedServiceStatus();
  await refreshState();
  startPolling();
}

function bindControls(): void {
  elements.saveSettings.addEventListener("click", () => {
    persistSettings();
    flashNote("Settings saved locally.");
  });

  elements.refreshState.addEventListener("click", () => {
    void refreshState(true);
  });

  elements.startService.addEventListener("click", () => {
    void startManagedService();
  });

  elements.stopService.addEventListener("click", () => {
    void stopManagedService();
  });
}

function hydrateSettings(): void {
  const stored = window.localStorage.getItem(STORAGE_KEY);
  let settings = defaults;
  if (stored) {
    try {
      settings = { ...defaults, ...JSON.parse(stored) as Partial<Settings> };
    } catch {
      settings = defaults;
    }
  }
  elements.repoPath.value = settings.repoPath;
  elements.binary.value = settings.binary;
  elements.host.value = settings.host;
  elements.port.value = String(settings.port);
  elements.token.value = settings.token;
  elements.limit.value = String(settings.limit);
  elements.refreshOnStart.checked = settings.refreshOnStart;
}

function persistSettings(): Settings {
  const settings = readSettings();
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
  return settings;
}

function readSettings(): Settings {
  return {
    repoPath: elements.repoPath.value.trim(),
    binary: elements.binary.value.trim() || defaults.binary,
    host: elements.host.value.trim() || defaults.host,
    port: Number(elements.port.value) || defaults.port,
    token: elements.token.value.trim(),
    limit: Math.max(3, Math.min(50, Number(elements.limit.value) || defaults.limit)),
    refreshOnStart: elements.refreshOnStart.checked,
  };
}

async function refreshState(forceRefresh = false): Promise<void> {
  const settings = persistSettings();
  if (!settings.host || !settings.port) {
    renderError("Set a host and port for the agent service.");
    return;
  }

  try {
    const nextState = await fetchAgentState(settings, forceRefresh);
    state = nextState;
    renderState(nextState, settings.limit);
    setConnection(true, "Connected");
  } catch (error) {
    setConnection(false, "Disconnected");
    renderError(error instanceof Error ? error.message : String(error));
  }
}

async function fetchAgentState(settings: Settings, forceRefresh: boolean): Promise<AgentState> {
  const url = new URL(`/state${forceRefresh ? "?refresh=1" : ""}`, serviceOrigin(settings));
  const response = await fetch(url.toString(), {
    headers: buildHeaders(settings.token),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Agent service returned ${response.status}: ${text}`);
  }
  return await response.json() as AgentState;
}

async function postTriageAction(path: string, payload: Record<string, unknown>): Promise<void> {
  const settings = persistSettings();
  const response = await fetch(new URL(path, serviceOrigin(settings)).toString(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...buildHeaders(settings.token),
    },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Agent service returned ${response.status}: ${text}`);
  }
  state = await response.json() as AgentState;
  renderState(state, settings.limit);
  setConnection(true, "Connected");
}

function renderState(nextState: AgentState, limit: number): void {
  const summary = nextState.summary ?? {};
  elements.headline.textContent = summary.headline || "No active findings";
  elements.subtitle.textContent = summary.subtitle || "The active queue is currently quiet.";
  elements.updatedAt.textContent = nextState.generated_at
    ? `Updated ${new Date(nextState.generated_at).toLocaleString()}`
    : "No state timestamp";

  const activeActions = (nextState.actions ?? []).slice(0, limit);
  const triagedEntries = collectTriaged(nextState);

  elements.activeCount.textContent = String(activeActions.length);
  elements.newCount.textContent = String(summary.new_findings ?? 0);
  elements.changedCount.textContent = String(summary.changed_file_count ?? 0);
  elements.triagedCount.textContent = String(triagedEntries.length);

  renderActiveQueue(activeActions);
  renderTriaged(triagedEntries);
  void syncTraySnapshot({
    headline: elements.headline.textContent || undefined,
    subtitle: elements.subtitle.textContent || undefined,
    activeCount: activeActions.length,
    newCount: summary.new_findings ?? 0,
    changedCount: summary.changed_file_count ?? 0,
    triagedCount: triagedEntries.length,
    topActionTitle: activeActions[0]?.title,
    topActionPath: activeActions[0] ? (activeActions[0].absolute_file || activeActions[0].file) : undefined,
    topActionLine: activeActions[0]?.line,
  });
}

function renderActiveQueue(actions: Action[]): void {
  if (actions.length === 0) {
    elements.activeQueue.className = "action-list empty-state";
    elements.activeQueue.textContent = "No ranked actions right now.";
    return;
  }

  elements.activeQueue.className = "action-list";
  elements.activeQueue.innerHTML = "";
  for (const action of actions) {
    const card = document.createElement("article");
    card.className = "action-card";
    card.innerHTML = `
      <div class="action-meta">
        <span class="severity ${normalizeClassName(action.severity)}">${action.severity}</span>
        <span class="muted-label">${escapeHtml(action.reason || "ranked by severity")}</span>
      </div>
      <h3>${escapeHtml(action.title)}</h3>
      <p>${escapeHtml(action.subtitle || "")}</p>
      <div class="action-footer">
        <span class="location">${escapeHtml(action.file)}:${action.line}</span>
        <div class="action-buttons">
          <button data-action="open">Open</button>
          <button class="secondary" data-action="snooze-4">Snooze 4h</button>
          <button class="secondary" data-action="snooze-24">Snooze 24h</button>
          <button class="danger secondary" data-action="dismiss">Dismiss</button>
        </div>
      </div>
    `;
    bindActionCard(card, action);
    elements.activeQueue.append(card);
  }
}

function renderTriaged(entries: Array<{ id: string; entry: TriageEntry; finding?: Finding }>): void {
  if (entries.length === 0) {
    elements.triagedList.className = "action-list empty-state";
    elements.triagedList.textContent = "Nothing triaged yet.";
    return;
  }

  elements.triagedList.className = "action-list";
  elements.triagedList.innerHTML = "";
  for (const item of entries) {
    const title = item.finding?.message || item.id;
    const location = item.finding ? `${item.finding.file}:${item.finding.line}` : item.id;
    const detail = item.entry.status === "snoozed" && item.entry.snoozed_until
      ? `Snoozed until ${new Date(item.entry.snoozed_until).toLocaleString()}`
      : `Dismissed ${item.entry.updated_at ? new Date(item.entry.updated_at).toLocaleString() : "recently"}`;
    const card = document.createElement("article");
    card.className = "action-card";
    card.innerHTML = `
      <div class="action-meta">
        <span class="severity info">${escapeHtml(item.entry.status)}</span>
        <span class="muted-label">${escapeHtml(detail)}</span>
      </div>
      <h3>${escapeHtml(title)}</h3>
      <p>${escapeHtml(location)}</p>
      <div class="action-footer">
        <span class="location">${escapeHtml(item.id)}</span>
        <div class="action-buttons">
          <button class="secondary" data-action="restore">Restore</button>
        </div>
      </div>
    `;
    const restoreButton = card.querySelector<HTMLButtonElement>("[data-action='restore']");
    restoreButton?.addEventListener("click", () => {
      void handleRestore(item.id);
    });
    elements.triagedList.append(card);
  }
}

function bindActionCard(card: HTMLElement, action: Action): void {
  card.querySelector<HTMLButtonElement>("[data-action='open']")?.addEventListener("click", () => {
    void handleOpenAction(action);
  });
  card.querySelector<HTMLButtonElement>("[data-action='dismiss']")?.addEventListener("click", () => {
    void handleDismiss(action.id);
  });
  card.querySelector<HTMLButtonElement>("[data-action='snooze-4']")?.addEventListener("click", () => {
    void handleSnooze(action.id, 4);
  });
  card.querySelector<HTMLButtonElement>("[data-action='snooze-24']")?.addEventListener("click", () => {
    void handleSnooze(action.id, 24);
  });
}

async function handleDismiss(actionId: string): Promise<void> {
  await postTriageAction("/triage/dismiss", { action_id: actionId });
  flashNote("Action dismissed.");
}

async function handleSnooze(actionId: string, hours: number): Promise<void> {
  await postTriageAction("/triage/snooze", { action_id: actionId, hours });
  flashNote(`Action snoozed for ${hours}h.`);
}

async function handleRestore(actionId: string): Promise<void> {
  await postTriageAction("/triage/restore", { action_id: actionId });
  flashNote("Action restored.");
}

async function handleOpenAction(action: Action): Promise<void> {
  const filePath = action.absolute_file || action.file;
  if (await invoke("open_in_editor", { filePath, line: action.line })) {
    flashNote("Opened target in editor.");
    return;
  }

  flashNote("No desktop editor integration available in browser preview.");
}

async function startManagedService(): Promise<void> {
  const settings = persistSettings();
  if (!settings.repoPath) {
    flashNote("Set a repo path before starting the agent.");
    return;
  }

  if (!settings.token) {
    settings.token = randomToken();
    elements.token.value = settings.token;
    persistSettings();
  }

  const result = await invoke<ServiceStatus>("start_agent_service", {
    repoPath: settings.repoPath,
    binary: settings.binary,
    host: settings.host,
    port: settings.port,
    token: settings.token,
    limit: settings.limit,
    refreshOnStart: settings.refreshOnStart,
  });

  if (!result) {
    flashNote("Managed service launch is only available inside the Tauri shell.");
    return;
  }

  flashNote(`Agent started at ${result.url ?? serviceOrigin(settings)}.`);
  await updateManagedServiceStatus();
  await refreshState(true);
}

async function stopManagedService(): Promise<void> {
  const result = await invoke<{ stopped: boolean }>("stop_agent_service");
  if (!result) {
    flashNote("Managed service stop is only available inside the Tauri shell.");
    return;
  }
  flashNote(result.stopped ? "Managed agent stopped." : "No managed agent was running.");
  await updateManagedServiceStatus();
}

async function updateManagedServiceStatus(): Promise<void> {
  const result = await invoke<ServiceStatus>("service_status");
  if (!result) {
    elements.serviceNote.textContent =
      "In browser preview, connect to an already running `skylos agent serve` instance. In Tauri, this panel can launch the local agent for you.";
    return;
  }

  elements.serviceNote.textContent = result.running && result.url
    ? `Managed agent running at ${result.url}`
    : "No managed agent is running from the companion yet.";
}

function startPolling(): void {
  stopPolling();
  pollingHandle = window.setInterval(() => {
    void refreshState();
  }, POLL_MS);
}

function stopPolling(): void {
  if (pollingHandle !== undefined) {
    window.clearInterval(pollingHandle);
    pollingHandle = undefined;
  }
}

function setConnection(connected: boolean, label: string): void {
  elements.connectionChip.textContent = label;
  elements.connectionChip.className = connected ? "chip" : "chip muted";
}

function renderError(message: string): void {
  elements.subtitle.textContent = message;
  elements.activeQueue.className = "action-list empty-state";
  elements.activeQueue.textContent = message;
  void syncTraySnapshot({
    headline: "Agent unavailable",
    subtitle: message,
    activeCount: 0,
    newCount: 0,
    changedCount: 0,
    triagedCount: 0,
  });
}

function flashNote(message: string): void {
  elements.serviceNote.textContent = message;
}

function collectTriaged(nextState: AgentState): Array<{ id: string; entry: TriageEntry; finding?: Finding }> {
  const findings = new Map((nextState.findings ?? []).map((finding) => [finding.fingerprint, finding]));
  return Object.entries(nextState.triage ?? {})
    .map(([id, entry]) => ({ id, entry, finding: findings.get(id) }))
    .sort((left, right) => left.id.localeCompare(right.id));
}

function serviceOrigin(settings: Settings): string {
  return `http://${settings.host}:${settings.port}`;
}

function buildHeaders(token: string): HeadersInit {
  return token ? { "X-Skylos-Agent-Token": token } : {};
}

async function invoke<T>(command: string, args?: Record<string, unknown>): Promise<T | null> {
  const runtimeInvoke = await getInvoke();
  if (!runtimeInvoke) {
    return null;
  }
  return await runtimeInvoke(command, args) as T;
}

async function getInvoke(): Promise<((command: string, args?: Record<string, unknown>) => Promise<unknown>) | null> {
  if (invokeFn) {
    return invokeFn;
  }
  if (!isTauriRuntime()) {
    return null;
  }
  const mod = await import("@tauri-apps/api/core");
  invokeFn = mod.invoke;
  return invokeFn;
}

async function bindRuntimeEvents(): Promise<void> {
  if (!isTauriRuntime()) {
    return;
  }

  const mod = await import("@tauri-apps/api/event");
  await mod.listen(REFRESH_EVENT, () => {
    void updateManagedServiceStatus();
    void refreshState(true);
  });
}

async function syncTraySnapshot(snapshot: TraySnapshot): Promise<void> {
  await invoke("update_tray_snapshot", { snapshot });
}

function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && Boolean(window.__TAURI_INTERNALS__);
}

function randomToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function byId(id: string): HTMLElement {
  const node = document.getElementById(id);
  if (!node) {
    throw new Error(`Missing DOM node: ${id}`);
  }
  return node;
}

function normalizeClassName(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-");
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#039;");
}
