// Unit tests for the tray menu action mapping module.
//
// Mirrors the pure helpers exercised on the Rust side under
// `crates/locket-app/src-tauri/src/tray.rs`. Keeps the wire contract
// pinned even when the webview is the only consumer.

import { describe, expect, it } from 'vitest';

import {
  TRAY_MENU_ACTIONS,
  trayActionAgentCommand,
  trayActionEnablement,
  trayActionRequiresSelection,
  trayActionSideEffect,
  trayActionToView,
  type TrayMenuAction,
  type TraySelectionState,
} from './menuActions';

describe('trayActionToView', () => {
  it('routes each action to the spec-defined view', () => {
    const cases: Array<[TrayMenuAction, ReturnType<typeof trayActionToView>]> = [
      ['open-app', 'dashboard'],
      ['lock-vault', null],
      ['unlock-vault', 'dashboard'],
      ['switch-profile', 'dashboard'],
      ['run-policy', 'policies'],
      ['start-scan', 'scan'],
      ['reveal-secret', 'secrets'],
      ['copy-secret', 'secrets'],
    ];
    for (const [action, expected] of cases) {
      expect(trayActionToView(action)).toBe(expected);
    }
  });

  it('treats lock-vault as the only headless action', () => {
    for (const action of TRAY_MENU_ACTIONS) {
      const view = trayActionToView(action);
      if (action === 'lock-vault') {
        expect(view).toBeNull();
      } else {
        expect(view).not.toBeNull();
      }
    }
  });
});

describe('trayActionSideEffect', () => {
  it('maps every action to a side effect', () => {
    const cases: Array<[TrayMenuAction, ReturnType<typeof trayActionSideEffect>]> = [
      ['open-app', 'none'],
      ['lock-vault', 'lock-vault'],
      ['unlock-vault', 'open-unlock-modal'],
      ['switch-profile', 'open-profile-switcher'],
      ['run-policy', 'refresh-policies'],
      ['start-scan', 'start-scan'],
      ['reveal-secret', 'reveal-selected-secret'],
      ['copy-secret', 'copy-selected-secret'],
    ];
    for (const [action, expected] of cases) {
      expect(trayActionSideEffect(action)).toBe(expected);
    }
  });
});

describe('trayActionAgentCommand', () => {
  it('pins the agent-backed completion path for each tray action', () => {
    const cases: Array<[TrayMenuAction, ReturnType<typeof trayActionAgentCommand>]> = [
      ['open-app', null],
      ['lock-vault', 'agent_lock'],
      ['unlock-vault', 'agent_unlock'],
      ['switch-profile', 'agent_set_active_profile'],
      ['run-policy', 'agent_list_policies'],
      ['start-scan', 'agent_scan'],
      ['reveal-secret', 'agent_reveal'],
      ['copy-secret', 'agent_copy_secret'],
    ];
    for (const [action, expected] of cases) {
      expect(trayActionAgentCommand(action)).toBe(expected);
    }
  });
});

describe('trayActionEnablement', () => {
  const matrix: Array<[TraySelectionState, boolean, string | null]> = [
    [
      { vault_unlocked: false, secret_selected: false },
      false,
      'Unlock the vault to use this action.',
    ],
    [
      { vault_unlocked: false, secret_selected: true },
      false,
      'Unlock the vault to use this action.',
    ],
    [
      { vault_unlocked: true, secret_selected: false },
      false,
      'Select a secret in the desktop list first.',
    ],
    [{ vault_unlocked: true, secret_selected: true }, true, null],
  ];

  it('gates reveal-secret and copy-secret on unlock and selection', () => {
    for (const action of ['reveal-secret', 'copy-secret'] as const) {
      for (const [selection, expectedEnabled, expectedReason] of matrix) {
        const result = trayActionEnablement(action, selection);
        expect(result.enabled).toBe(expectedEnabled);
        expect(result.disabledReason).toBe(expectedReason);
      }
    }
  });

  it('always enables selection-independent actions', () => {
    const states: TraySelectionState[] = [
      { vault_unlocked: false, secret_selected: false },
      { vault_unlocked: false, secret_selected: true },
      { vault_unlocked: true, secret_selected: false },
      { vault_unlocked: true, secret_selected: true },
    ];
    for (const action of TRAY_MENU_ACTIONS) {
      if (trayActionRequiresSelection(action)) {
        continue;
      }
      for (const state of states) {
        const result = trayActionEnablement(action, state);
        expect(result.enabled).toBe(true);
        expect(result.disabledReason).toBeNull();
      }
    }
  });

  it('flags reveal-secret and copy-secret as the only selection-aware actions', () => {
    for (const action of TRAY_MENU_ACTIONS) {
      const expected = action === 'reveal-secret' || action === 'copy-secret';
      expect(trayActionRequiresSelection(action)).toBe(expected);
    }
  });
});

it('ignores a tray event outside the routed menu actions', () => {
  const action = 'quit-app' as TrayMenuAction;
  expect(trayActionToView(action)).toBeNull();
  expect(trayActionSideEffect(action)).toBe('none');
  expect(trayActionAgentCommand(action)).toBeNull();
});
