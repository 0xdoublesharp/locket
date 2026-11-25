// Pure mapping module for the tray menu action contract.
//
// The Rust side (`crates/locket-app/src-tauri/src/tray.rs`) emits a
// `tray-menu-action` event with one of the kebab-case strings below.
// The webview maps that wire string to:
//
//   - the primary view to focus, and
//   - whether the action triggers a side-effect handler in `App.vue`.
//
// Keeping this logic in a vscode-free module lets us unit test the
// mapping contract without spinning up the Vue runtime or a Tauri
// webview.

export type TrayMenuAction =
  | 'open-app'
  | 'lock-vault'
  | 'unlock-vault'
  | 'switch-profile'
  | 'run-policy'
  | 'start-scan'
  | 'reveal-secret'
  | 'copy-secret';

export type TrayView =
  | 'dashboard'
  | 'secrets'
  | 'versions'
  | 'execution'
  | 'devices'
  | 'audit'
  | 'scan'
  | 'policies'
  | 'recovery'
  | 'settings';

/** Side-effect categories that the App-level handler invokes. */
export type TraySideEffect =
  | 'none'
  | 'lock-vault'
  | 'open-unlock-modal'
  | 'open-profile-switcher'
  | 'refresh-policies'
  | 'start-scan'
  | 'reveal-selected-secret'
  | 'copy-selected-secret';

/** Desktop command each tray action ultimately drives, when applicable. */
export type TrayAgentCommand =
  | 'agent_lock'
  | 'agent_unlock'
  | 'agent_set_active_profile'
  | 'agent_list_policies'
  | 'agent_scan'
  | 'agent_reveal'
  | 'agent_copy_secret';

/**
 * Vault + secret-selection state pushed into the Rust tray module via
 * `tray_set_selection`. Carries booleans only — never a secret name,
 * value, or id — so the tray surface remains metadata-only per the
 * desktop spec.
 */
export interface TraySelectionState {
  vault_unlocked: boolean;
  secret_selected: boolean;
}

/** Pure mirror of the Rust enablement matrix. Used by tests. */
export interface TrayMenuItemEnablement {
  enabled: boolean;
  disabledReason: string | null;
}

const SELECTION_AWARE_ACTIONS: ReadonlySet<TrayMenuAction> = new Set([
  'reveal-secret',
  'copy-secret',
]);

/** Whether the action depends on the (vault unlocked, secret selected) gate. */
export function trayActionRequiresSelection(action: TrayMenuAction): boolean {
  return SELECTION_AWARE_ACTIONS.has(action);
}

/**
 * Pure mirror of `tray::tray_menu_action_enablement`. Returns the same
 * (enabled, disabledReason) shape so the desktop tests pin the matrix
 * end-to-end with the Rust side.
 */
export function trayActionEnablement(
  action: TrayMenuAction,
  selection: TraySelectionState,
): TrayMenuItemEnablement {
  if (!trayActionRequiresSelection(action)) {
    return { enabled: true, disabledReason: null };
  }
  if (!selection.vault_unlocked) {
    return { enabled: false, disabledReason: 'Unlock the vault to use this action.' };
  }
  if (!selection.secret_selected) {
    return { enabled: false, disabledReason: 'Select a secret in the desktop list first.' };
  }
  return { enabled: true, disabledReason: null };
}

/**
 * Pure mapping from a tray action wire string to the primary view the
 * desktop should focus before any side-effect runs.
 */
export function trayActionToView(action: TrayMenuAction): TrayView | null {
  switch (action) {
    case 'open-app':
      return 'dashboard';
    case 'lock-vault':
      return null;
    case 'unlock-vault':
      return 'dashboard';
    case 'switch-profile':
      return 'dashboard';
    case 'run-policy':
      return 'policies';
    case 'start-scan':
      return 'scan';
    case 'reveal-secret':
    case 'copy-secret':
      return 'secrets';
    default:
      return null;
  }
}

/**
 * Pure mapping from a tray action wire string to the side-effect class
 * the App-level handler should run after focusing the view.
 */
export function trayActionSideEffect(action: TrayMenuAction): TraySideEffect {
  switch (action) {
    case 'open-app':
      return 'none';
    case 'lock-vault':
      return 'lock-vault';
    case 'unlock-vault':
      return 'open-unlock-modal';
    case 'switch-profile':
      return 'open-profile-switcher';
    case 'run-policy':
      return 'refresh-policies';
    case 'start-scan':
      return 'start-scan';
    case 'reveal-secret':
      return 'reveal-selected-secret';
    case 'copy-secret':
      return 'copy-selected-secret';
    default:
      return 'none';
  }
}

/** Agent-backed command path used by the App-level tray handler. */
export function trayActionAgentCommand(action: TrayMenuAction): TrayAgentCommand | null {
  switch (action) {
    case 'lock-vault':
      return 'agent_lock';
    case 'unlock-vault':
      return 'agent_unlock';
    case 'switch-profile':
      return 'agent_set_active_profile';
    case 'run-policy':
      return 'agent_list_policies';
    case 'start-scan':
      return 'agent_scan';
    case 'reveal-secret':
      return 'agent_reveal';
    case 'copy-secret':
      return 'agent_copy_secret';
    case 'open-app':
      return null;
    default:
      return null;
  }
}

/** All tray menu actions in spec order. */
export const TRAY_MENU_ACTIONS: readonly TrayMenuAction[] = [
  'open-app',
  'lock-vault',
  'unlock-vault',
  'switch-profile',
  'run-policy',
  'start-scan',
  'reveal-secret',
  'copy-secret',
];
