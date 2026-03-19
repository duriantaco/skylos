# Skylos Tauri Companion

Thin cross-platform desktop shell for the Skylos active-agent queue.

## What it does

- connects to the local Skylos agent API
- shows the repo headline and ranked action queue
- lets you dismiss, snooze, and restore actions
- can launch a managed `skylos agent serve` process from inside Tauri
- can open action targets in VS Code-family editors when running in Tauri
- adds a real tray/menu-bar surface with quick queue status, top-action open, refresh, stop-agent, and quit

## Why this exists

The VS Code extension stays editor-native. This companion is the always-on repo surface for:

- macOS menu bar / dock usage
- Windows tray-style usage
- Linux desktop usage
- future Tauri shells built on the same backend

The queue logic still lives in Skylos itself, not in the desktop app.

## Layout

- `src/` Vite frontend
- `src-tauri/` Rust shell

## Dev flow

1. Install frontend dependencies:

```bash
npm install
```

2. Start the desktop shell:

```bash
npm run tauri:dev
```

3. Inside the companion:

- set `Repo Path`
- click `Start Agent`
- the app will launch `skylos agent serve` with a session token

You can also run the agent yourself:

```bash
skylos agent serve /path/to/repo --token your-token
```

Then point the companion at that host/port/token.

## Notes

- The frontend also works in plain browser preview via `npm run dev`, but managed service launch and editor-opening only work inside Tauri.
- Inside Tauri, closing the window hides it instead of exiting. Use the tray/menu-bar entry to reopen or quit the companion.
- The desktop app is intentionally thin. If you want richer ranking or state behavior, change the agent backend rather than the Tauri UI first.
