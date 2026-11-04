import type {
  AuditLogRow,
  CommandPolicyRow,
  RuntimeSessionRow,
  ScanFindingRow,
  SecretRowMeta,
} from '../types/views';
export type StartHereTarget =
  'connect' | 'start-agent' | 'unlock' | 'refresh' | 'secret-editor' | 'policies';
export type StartHereTone = 'ok' | 'warn' | 'critical' | 'neutral';
export interface StartHereAction {
  id: string;
  title: string;
  detail: string;
  target: StartHereTarget;
  actionLabel: string;
  tone: StartHereTone;
}
export interface StartHereInput {
  setupComplete?: boolean;
  projectConnected: boolean;
  connected: boolean;
  lockLabel: string;
  secrets: SecretRowMeta[];
  policies: CommandPolicyRow[];
  sessions: RuntimeSessionRow[];
  auditRows: AuditLogRow[];
  findings: ScanFindingRow[];
  auditChainOk: boolean | null;
  secretsLoaded: boolean;
  policiesLoaded: boolean;
  lastScanAt?: string;
}
export function startHereActions(input: StartHereInput): StartHereAction[] {
  const action = (
    id: string,
    title: string,
    detail: string,
    target: StartHereTarget,
    actionLabel: string,
  ): StartHereAction[] => [{ id, title, detail, target, actionLabel, tone: 'neutral' }];
  if (!input.projectConnected)
    return action(
      'open-project',
      'Open a project',
      'Choose a project folder, or initialize Locket in a new folder.',
      'connect',
      'Connect project',
    );
  if (!input.connected)
    return action(
      'start-agent',
      'Start the local agent',
      'The desktop app can start the local agent for this project.',
      'start-agent',
      'Start agent',
    );
  if (input.lockLabel !== 'Unlocked')
    return action(
      'unlock',
      'Unlock this project',
      'Use your system keychain or a passphrase to unlock for a limited time.',
      'unlock',
      'Unlock',
    );
  if (input.setupComplete) return [];
  if (!input.secretsLoaded || !input.policiesLoaded)
    return action(
      'load-project',
      'Load project metadata',
      'Refresh to check stored variables and commands. If loading fails, fix the connection and retry.',
      'refresh',
      'Retry load',
    );
  if (input.secrets.length === 0)
    return action(
      'add-secret',
      'Import or add variables',
      'Import an env file or add a value for this environment.',
      'secret-editor',
      'Add variables',
    );
  if (input.policies.length === 0)
    return action(
      'create-policy',
      'Create a command',
      'Choose the command and the variables it may use.',
      'policies',
      'Create command',
    );
  if (input.sessions.length === 0)
    return action(
      'run-command',
      'Run your first command',
      'Launch an approved command in your terminal.',
      'policies',
      'Open commands',
    );
  return [];
}
