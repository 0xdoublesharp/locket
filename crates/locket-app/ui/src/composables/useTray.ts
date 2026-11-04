// Reactive tray state pusher. Watches the typed agent status and
// error refs from `useAgent`, derives the matching `TrayState`, and
// invokes the Rust-side `tray_set_state` command on every change.
//
// Outside a Tauri webview (e.g. during a plain `vite preview` shell)
// invoke is a no-op so the same composable can power the dev surface
// without crashing on the missing IPC bridge.

import { watch, type Ref } from 'vue';
import { invoke, isTauri } from '@tauri-apps/api/core';

import type { AgentClientError, AgentStatus } from '../agent/types';

export type TrayState =
  'agent-unlocked' | 'agent-locked' | 'agent-stopped' | 'scan-warning' | 'error-degraded';

/**
 * Pure mapping from the current `AgentStatus` and `AgentClientError`
 * to the tray icon state the Rust shell should render.
 *
 * Decision order mirrors the desktop spec tray privacy rules:
 *
 * 1. Agent unreachable (`unavailable`) → `agent-stopped`.
 * 2. Wire faults (`protocol`, `rejected`) → `error-degraded`.
 * 3. Unresolved scan warnings from a successful status response.
 * 4. Lock state from a successful status response.
 * 5. Loading / pre-poll → `agent-stopped` so the menu bar reflects
 *    "no live agent" until the first poll lands.
 */
export function deriveTrayState(
  status: AgentStatus | null,
  error: AgentClientError | null,
): TrayState {
  if (error !== null) {
    if (error.kind === 'unavailable') {
      return 'agent-stopped';
    }
    return 'error-degraded';
  }
  if (status === null) {
    return 'agent-stopped';
  }
  if (status.scan_warning_count > 0) {
    return 'scan-warning';
  }
  switch (status.lock_state) {
    case 'unlocked':
      return 'agent-unlocked';
    case 'locked':
      return 'agent-locked';
    case 'unknown':
      return 'error-degraded';
    default:
      return 'error-degraded';
  }
}

/**
 * Watch the agent status and error refs and push a tray state update
 * to Rust whenever the derived state changes. Safe to call outside a
 * Tauri webview — the underlying invoke is skipped when `isTauri()`
 * is false.
 */
export function useTray(
  status: Ref<AgentStatus | null>,
  error: Ref<AgentClientError | null>,
): void {
  let lastPushed: TrayState | null = null;

  async function push(next: TrayState): Promise<void> {
    if (!isTauri()) {
      lastPushed = next;
      return;
    }
    try {
      await invoke<void>('tray_set_state', { state: next });
      lastPushed = next;
    } catch {
      // Tray rendering failures are local-only and must never block
      // the rest of the app. The next state change will retry.
    }
  }

  watch(
    [status, error],
    ([nextStatus, nextError]) => {
      const desired = deriveTrayState(nextStatus, nextError);
      if (desired === lastPushed) {
        return;
      }
      void push(desired);
    },
    { immediate: true },
  );
}
