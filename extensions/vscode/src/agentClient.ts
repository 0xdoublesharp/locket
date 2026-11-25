import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';

const PROTOCOL_VERSION = 1;
const DEFAULT_MAX_MESSAGE_SIZE = 1024 * 1024;
const DEFAULT_CONNECT_TIMEOUT_MS = 2_000;

export type AgentMethod =
  | 'Status'
  | 'Unlock'
  | 'Lock'
  | 'RegisterClient'
  | 'RevokeClient'
  | 'RequestGrant'
  | 'RevokeGrant'
  | 'ExpireGrant'
  | 'ResolveReference'
  | 'PrepareExec'
  | 'ScanKnownValues'
  | 'ListPolicies'
  | 'ListAudit'
  | 'SetActiveProfile'
  | 'Reveal'
  | 'Copy'
  | 'SubscribeStatus'
  | 'CancelSubscription'
  | 'ClientHello'
  | 'RegisterIdeEnvSession'
  | 'IdeEnvSession';

export type LockState = 'locked' | 'unlocked' | 'unknown';
export type StatusEventKind = 'status' | 'heartbeat';

export interface StatusPayload {
  readonly lock_state: LockState;
  readonly project_id?: string | null;
  readonly profile_name?: string | null;
  readonly live_grant_count: number;
  readonly agent_version: string;
  readonly unlock_ttl_seconds?: number | null;
  readonly running_session_count?: number;
  readonly scan_warning_count?: number;
  readonly recent_audit_status?: 'unknown' | 'ok' | 'warning';
  readonly pinned_reference_warning_count?: number;
}

export interface StatusEvent extends StatusPayload {
  readonly kind: StatusEventKind;
  readonly sequence: number;
}

export interface AgentClientOptions {
  readonly socketPath?: string;
  readonly connectTimeoutMs?: number;
  readonly maxMessageSize?: number;
}

export interface AgentProtocolErrorBody {
  readonly error: string;
  readonly message: string;
  readonly retryable: boolean;
}

export interface ErrorDisplayCopy {
  readonly reason: string;
  readonly nextAction: string;
}

export interface RequestEnvelope {
  readonly v: typeof PROTOCOL_VERSION;
  readonly id: string;
  readonly kind: AgentMethod;
  readonly payload: unknown;
}

export interface SuccessEnvelope {
  readonly v: typeof PROTOCOL_VERSION;
  readonly id: string;
  readonly ok: true;
  readonly payload: unknown;
}

export interface ErrorEnvelope {
  readonly v: typeof PROTOCOL_VERSION;
  readonly id: string;
  readonly ok: false;
  readonly error: string;
  readonly message: string;
  readonly retryable: boolean;
}

export type ResponseEnvelope = SuccessEnvelope | ErrorEnvelope;

type SocketFactory = (socketPath: string) => net.Socket;

export class AgentClientError extends Error {
  public readonly kind: 'unavailable' | 'protocol' | 'agent';
  public readonly code?: string;
  public readonly retryable: boolean;
  public readonly displayReason?: string;
  public readonly nextAction?: string;

  private constructor(
    kind: AgentClientError['kind'],
    message: string,
    retryable: boolean,
    code?: string,
    displayCopy?: ErrorDisplayCopy,
  ) {
    super(message);
    this.name = 'AgentClientError';
    this.kind = kind;
    this.code = code;
    this.retryable = retryable;
    this.displayReason = displayCopy?.reason;
    this.nextAction = displayCopy?.nextAction;
  }

  public static unavailable(message: string): AgentClientError {
    return new AgentClientError('unavailable', message, true, 'AgentUnavailable', displayCopyForAgentCode('AgentUnavailable'));
  }

  public static protocol(message: string): AgentClientError {
    return new AgentClientError('protocol', message, false);
  }

  public static agent(error: AgentProtocolErrorBody): AgentClientError {
    const displayCopy = displayCopyForAgentCode(error.error) ?? {
      reason: 'The agent rejected the request.',
      nextAction: 'See the agent logs for details.',
    };
    return new AgentClientError('agent', error.message, error.retryable, error.error, displayCopy);
  }
}

const ERROR_DISPLAY_COPY: Record<string, ErrorDisplayCopy> = {
  InvalidReference: {
    reason: 'The Locket reference is invalid.',
    nextAction: 'Fix the reference syntax, profile, key, source, or version.',
  },
  GitWorktreeRequired: {
    reason: 'This command requires a Git worktree.',
    nextAction: 'Run the command inside a Git worktree or scan an explicit path.',
  },
  InvalidSecretName: {
    reason: 'The secret name is invalid.',
    nextAction: 'Use an uppercase environment-style name.',
  },
  InvalidProfileName: {
    reason: 'The profile name is invalid.',
    nextAction: 'Use a lowercase profile name such as dev or staging.',
  },
  PolicyValidationIncomplete: {
    reason: 'Policy validation could not finish.',
    nextAction: 'Start or unlock the agent, then rerun policy validation.',
  },
  InvalidPolicy: {
    reason: 'The policy is invalid.',
    nextAction: 'Fix the policy document and retry.',
  },
  PolicyNotFound: {
    reason: 'The policy was not found.',
    nextAction: 'Add the policy or choose an existing policy name.',
  },
  EnvironmentConflict: {
    reason: 'Environment variable injection would overwrite a protected name.',
    nextAction: 'Rename the variable or change the policy override mode.',
  },
  MetadataInvalid: {
    reason: 'Metadata is invalid.',
    nextAction: 'Remove unsupported characters or values and retry.',
  },
  MetadataLooksLikeSecret: {
    reason: 'Metadata looks like secret material.',
    nextAction: 'Remove the secret-like metadata or store it as a secret.',
  },
  ConfirmationFailed: {
    reason: 'The confirmation text did not match.',
    nextAction: 'Retry and type the requested confirmation exactly.',
  },
  TtyRequired: {
    reason: 'An interactive terminal is required.',
    nextAction: 'Retry from an interactive terminal.',
  },
  ScanFindingBlocked: {
    reason: 'Scan findings blocked the command.',
    nextAction: 'Review the findings, rotate exposed values, or suppress intentional matches.',
  },
  SecretAlreadyExists: {
    reason: 'The secret already exists.',
    nextAction: 'Use rotate/update behavior or choose a different source.',
  },
  AccessDenied: {
    reason: 'Policy or trust rules denied the action.',
    nextAction: 'Request the required grant, policy change, or team role.',
  },
  TeamRoleDenied: {
    reason: 'Your team role does not allow this action.',
    nextAction: 'Ask an owner or maintainer to perform or authorize the action.',
  },
  ProjectRootUntrusted: {
    reason: 'The project root is not trusted.',
    nextAction: 'Run locket project trust-root from the intended project path.',
  },
  ProjectNotFound: {
    reason: 'No Locket project was found.',
    nextAction: 'Run locket init or move into an existing Locket project.',
  },
  UnlockRequired: {
    reason: 'The vault is locked.',
    nextAction: 'Run locket unlock or approve an agent unlock prompt.',
  },
  GrantRequired: {
    reason: 'No live grant covers this action.',
    nextAction: 'Run locket allow or refresh the shell or editor grant.',
  },
  UserVerificationFailed: {
    reason: 'Local user verification failed.',
    nextAction: 'Retry verification or use a configured recovery path.',
  },
  SecretVersionExpired: {
    reason: 'The pinned secret version is expired.',
    nextAction: 'Update the reference to the current version or rotate with a new grace window.',
  },
  SecretDeleted: {
    reason: 'The selected secret source is deleted.',
    nextAction: 'Choose another source or restore from a trusted backup.',
  },
  SecretNotFound: {
    reason: 'The secret was not found.',
    nextAction: 'Check the secret name, profile, and source.',
  },
  ProfileNotFound: {
    reason: 'The profile was not found.',
    nextAction: 'Choose an existing profile or create one.',
  },
  AgentUnavailable: {
    reason: 'The local agent is unavailable.',
    nextAction: 'Run locket agent start, then retry.',
  },
  AgentSocketInUse: {
    reason: 'The agent socket is already in use.',
    nextAction: 'Stop the stale agent or retry in direct CLI mode.',
  },
  AutomationClientNotTrusted: {
    reason: 'The automation client is not trusted.',
    nextAction: 'Register the client or fix its policy scope.',
  },
  AutomationClientReplayDetected: {
    reason: 'An automation client replay was detected.',
    nextAction: 'Retry with a fresh nonce and rotate the client key if replay is suspected.',
  },
  ExternalSourceUnavailable: {
    reason: 'An external environment source is unavailable.',
    nextAction: 'Start or fix the external provider and retry.',
  },
  UpdateManifestInvalid: {
    reason: 'The update manifest is invalid.',
    nextAction: 'Refresh the manifest source or use a trusted release artifact.',
  },
  SecretVersionOverflow: {
    reason: 'The secret version counter cannot advance.',
    nextAction: 'Inspect the store metadata before retrying.',
  },
  CorruptDb: {
    reason: 'The local database appears corrupt.',
    nextAction: 'Run diagnostics and restore from a trusted backup if needed.',
  },
  StorageBusy: {
    reason: 'Another Locket process is writing.',
    nextAction: 'Wait for the other command to finish, then retry.',
  },
  SchemaNewerThanBinary: {
    reason: 'The store schema is newer than this binary supports.',
    nextAction: 'Upgrade Locket and retry.',
  },
  AuditIntegrityFailed: {
    reason: 'Audit chain verification failed.',
    nextAction: 'Investigate store tampering or restore from backup.',
  },
  KeychainUnavailable: {
    reason: 'The keychain is unavailable.',
    nextAction: 'Unlock with passphrase fallback or run recovery.',
  },
  LostRecoveryCode: {
    reason: 'The recovery code is missing.',
    nextAction: 'Rotate recovery while the vault is still unlocked.',
  },
  LostKeychainEntry: {
    reason: 'The keychain entry is missing.',
    nextAction: 'Run locket recover with the recovery code.',
  },
  UnrecoverableVault: {
    reason: 'The vault cannot be recovered on this device.',
    nextAction: 'Restore from another trusted device or reinitialize the project.',
  },
  BundleVerificationFailed: {
    reason: 'The sealed bundle failed verification.',
    nextAction: 'Request a fresh bundle or verify it on an addressed device.',
  },
  InviteExpired: {
    reason: 'The invite has expired.',
    nextAction: 'Ask a maintainer for a fresh invite.',
  },
  TeamBundleConflict: {
    reason: 'The team bundle conflicts with local state.',
    nextAction: 'Choose a metadata-only conflict resolution path.',
  },
  DeviceRevoked: {
    reason: 'The device has been revoked.',
    nextAction: 'Add a new trusted device or request a fresh team invite.',
  },
  ReplayDetected: {
    reason: 'A replayed invite or request was detected.',
    nextAction: 'Request a fresh invite or retry with a new nonce.',
  },
  DeviceDescriptorInvalid: {
    reason: 'The device descriptor is invalid.',
    nextAction: 'Recreate the descriptor on the trusted device.',
  },
  InviteSignatureInvalid: {
    reason: 'The invite signature is invalid.',
    nextAction: 'Reject the invite and request a new one from the issuer.',
  },
};

export function displayCopyForAgentCode(code: string): ErrorDisplayCopy | undefined {
  return ERROR_DISPLAY_COPY[code];
}

export class AgentClient {
  private readonly socketPath: string;
  private readonly connectTimeoutMs: number;
  private readonly maxMessageSize: number;
  private readonly socketFactory: SocketFactory;
  private nextRequestId = 1;

  public constructor(options: AgentClientOptions = {}, socketFactory: SocketFactory = connectSocket) {
    this.socketPath = options.socketPath ?? resolveAgentSocketPath();
    this.connectTimeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
    this.maxMessageSize = options.maxMessageSize ?? DEFAULT_MAX_MESSAGE_SIZE;
    this.socketFactory = socketFactory;
  }

  public async status(): Promise<StatusPayload> {
    return this.invoke<StatusPayload>('Status', {});
  }

  public dispose(): void {
    // Connections are opened per request and closed immediately.
  }

  public async invoke<TPayload>(method: AgentMethod, payload: unknown): Promise<TPayload> {
    const request = this.requestEnvelope(method, payload);
    const socket = await this.openSocket();

    try {
      socket.write(encodeFrame(request, this.maxMessageSize));
      const response = await readOneResponse(socket, this.maxMessageSize);
      if (response.id !== request.id) {
        throw AgentClientError.protocol('agent response id did not match request id');
      }
      return unwrapResponse<TPayload>(response);
    } finally {
      socket.end();
      socket.destroy();
    }
  }

  public async subscribeStatus(
    onEvent: (event: StatusEvent) => void,
    onError: (error: AgentClientError) => void,
  ): Promise<{ dispose: () => void }> {
    const request = this.requestEnvelope('SubscribeStatus', {});
    const socket = await this.openSocket();
    let buffer = Buffer.alloc(0);
    let disposed = false;

    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      try {
        while (buffer.length >= 4) {
          const decoded = tryDecodeFrame(buffer, this.maxMessageSize);
          if (decoded === undefined) {
            return;
          }
          buffer = buffer.subarray(decoded.consumed);
          if (decoded.response.id !== request.id) {
            throw AgentClientError.protocol('agent stream response id did not match request id');
          }
          onEvent(unwrapResponse<StatusEvent>(decoded.response));
        }
      } catch (error) {
        if (!disposed) {
          disposed = true;
          onError(toClientError(error));
        }
        socket.destroy();
      }
    });
    socket.on('error', (error: Error) => {
      if (!disposed) {
        disposed = true;
        onError(AgentClientError.unavailable(error.message));
      }
    });
    socket.on('close', () => {
      // Surface a typed unavailable error when the agent closes the
      // stream socket without first sending an error envelope so the
      // status-bar controller can reconnect with backoff.
      if (!disposed) {
        disposed = true;
        onError(AgentClientError.unavailable('agent status stream closed'));
      }
    });
    socket.write(encodeFrame(request, this.maxMessageSize));

    return {
      dispose: () => {
        disposed = true;
        socket.end();
        socket.destroy();
      },
    };
  }

  private requestEnvelope(method: AgentMethod, payload: unknown): RequestEnvelope {
    const id = `vscode-${Date.now()}-${this.nextRequestId}`;
    this.nextRequestId += 1;
    return { v: PROTOCOL_VERSION, id, kind: method, payload };
  }

  private async openSocket(): Promise<net.Socket> {
    const socket = this.socketFactory(this.socketPath);
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        socket.destroy();
        reject(AgentClientError.unavailable('agent socket connection timed out'));
      }, this.connectTimeoutMs);

      socket.once('connect', () => {
        clearTimeout(timeout);
        resolve(socket);
      });
      socket.once('error', (error: Error) => {
        clearTimeout(timeout);
        reject(AgentClientError.unavailable(error.message));
      });
    });
  }
}

interface EndpointPlatform {
  readonly platform: NodeJS.Platform;
  readonly home: string;
  readonly windowsSid?: () => string;
}

function currentWindowsSid(environment: NodeJS.ProcessEnv): string {
  const systemRoot = environment.SystemRoot ?? environment.SYSTEMROOT ?? 'C:\\Windows';
  try {
    const output = execFileSync(path.win32.join(systemRoot, 'System32', 'whoami.exe'), ['/user', '/fo', 'csv', '/nh'], {
      encoding: 'utf8', timeout: DEFAULT_CONNECT_TIMEOUT_MS, maxBuffer: 16_384, windowsHide: true,
    });
    const match = /,"(S-\d+(?:-\d+)+)"\s*$/u.exec(output.trim());
    if (match?.[1] !== undefined) { return match[1]; }
  } catch { /* Report a stable error without process output or user identity. */ }
  throw AgentClientError.unavailable('Unable to determine the Windows agent pipe. Set LOCKET_AGENT_SOCKET explicitly.');
}

export function resolveAgentSocketPath(
  environment: NodeJS.ProcessEnv = process.env,
  platform: EndpointPlatform = { platform: process.platform, home: os.homedir() },
): string {
  const override = environment.LOCKET_AGENT_SOCKET?.trim();
  if (override !== undefined && override.length > 0) {
    return override;
  }
  if (platform.platform === 'win32') {
    const sid = (platform.windowsSid ?? (() => currentWindowsSid(environment)))();
    if (!/^S-\d+(?:-\d+)+$/u.test(sid)) {
      throw AgentClientError.unavailable('Unable to determine the Windows agent pipe. Set LOCKET_AGENT_SOCKET explicitly.');
    }
    return `\\\\.\\pipe\\locket-agent-${sid}`;
  }
  if (platform.platform === 'darwin') {
    return path.posix.join(platform.home, 'Library', 'Application Support', 'locket', 'agent.sock');
  }
  if (platform.platform === 'linux' && environment.XDG_RUNTIME_DIR) {
    return path.posix.join(environment.XDG_RUNTIME_DIR, 'locket', 'agent.sock');
  }
  return path.posix.join(platform.home, '.locket', 'agent.sock');
}

export function encodeFrame(envelope: RequestEnvelope, maxMessageSize = DEFAULT_MAX_MESSAGE_SIZE): Buffer {
  const payload = Buffer.from(JSON.stringify(envelope), 'utf8');
  if (payload.length > maxMessageSize) {
    throw AgentClientError.protocol('agent request frame exceeds maximum size');
  }
  const frame = Buffer.allocUnsafe(4 + payload.length);
  frame.writeUInt32LE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}

function readOneResponse(socket: net.Socket, maxMessageSize: number): Promise<ResponseEnvelope> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      try {
        const decoded = tryDecodeFrame(buffer, maxMessageSize);
        if (decoded !== undefined) {
          resolve(decoded.response);
        }
      } catch (error) {
        reject(error);
      }
    });
    socket.once('error', (error: Error) => {
      reject(AgentClientError.unavailable(error.message));
    });
    socket.once('close', () => {
      reject(AgentClientError.unavailable('agent socket closed before response'));
    });
  });
}

function tryDecodeFrame(
  buffer: Buffer,
  maxMessageSize: number,
): { response: ResponseEnvelope; consumed: number } | undefined {
  if (buffer.length < 4) {
    return undefined;
  }
  const length = buffer.readUInt32LE(0);
  if (length > maxMessageSize) {
    throw AgentClientError.protocol('agent response frame exceeds maximum size');
  }
  const consumed = 4 + length;
  if (buffer.length < consumed) {
    return undefined;
  }
  let response: unknown;
  try {
    response = JSON.parse(buffer.subarray(4, consumed).toString('utf8')) as unknown;
  } catch (error) {
    throw AgentClientError.protocol(error instanceof Error ? error.message : 'agent response JSON is invalid');
  }
  return { response: parseResponseEnvelope(response), consumed };
}

function parseResponseEnvelope(value: unknown): ResponseEnvelope {
  if (!isRecord(value) || value.v !== PROTOCOL_VERSION || typeof value.id !== 'string') {
    throw AgentClientError.protocol('agent response envelope is invalid');
  }
  if (value.ok === true && 'payload' in value) {
    return { v: PROTOCOL_VERSION, id: value.id, ok: true, payload: value.payload };
  }
  if (
    value.ok === false &&
    typeof value.error === 'string' &&
    typeof value.message === 'string' &&
    typeof value.retryable === 'boolean'
  ) {
    return {
      v: PROTOCOL_VERSION,
      id: value.id,
      ok: false,
      error: value.error,
      message: value.message,
      retryable: value.retryable,
    };
  }
  throw AgentClientError.protocol('agent response envelope is invalid');
}

function unwrapResponse<TPayload>(response: ResponseEnvelope): TPayload {
  if (!response.ok) {
    throw AgentClientError.agent(response);
  }
  return response.payload as TPayload;
}

function connectSocket(socketPath: string): net.Socket {
  return net.createConnection(socketPath);
}

function toClientError(error: unknown): AgentClientError {
  if (error instanceof AgentClientError) {
    return error;
  }
  if (error instanceof Error) {
    return AgentClientError.protocol(error.message);
  }
  return AgentClientError.protocol('unknown agent client failure');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
