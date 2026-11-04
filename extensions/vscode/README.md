# Locket VS Code Extension

This package hosts the VS Code extension backed by the local Locket
agent. It includes a TypeScript agent socket client for the v1 framed
JSON protocol, project-aware commands, and tests for the protocol and
command handlers.

## Project workflow

Trust the workspace and install the matching Locket CLI on an absolute PATH outside the project. The extension reads the active editor or terminal directory, finds its Locket project through the CLI, and uses the stored project/profile IDs. With multiple workspace folders, it asks you to choose only when the active editor and terminal do not identify one.

Unlock and audit use the project's resolved local store. Reveal and Copy ask for a portable secret name and open an interactive CLI terminal. The CLI uses the project's current profile and owns consent, local verification, and clipboard expiry. The extension does not capture plaintext or announce that a copy succeeded. Reveal writes plaintext to the terminal, where it can remain in scrollback. Dangerous-profile reads may require explicit CLI consent; the extension never supplies bypass flags. Switching profiles asks for the target name and, when required by the agent, a typed dangerous-profile confirmation.

Run Policy lists saved policies and launches the selected command in an integrated terminal. CLI confirmations and exit status remain visible there. Create Terminal registers a names-only IDE session for that terminal. Project sessions are never installed in the global terminal environment.

Scan Workspace opens `locket scan --require-known` in an integrated terminal at the resolved project root. The CLI scans files and reports redacted findings and coverage there; an unavailable vault produces an explicit error. Starting the terminal does not indicate that the scan completed.

Agent connections use the same defaults as the CLI: macOS Application Support, Linux's `XDG_RUNTIME_DIR` (falling back to `~/.locket`), or the current Windows user's SID-scoped named pipe. `LOCKET_AGENT_SOCKET` overrides discovery.

## Build

Use Node.js 24 or newer for development and packaging. The extension still
supports VS Code 1.80 and compiles against that host's API declarations.

```sh
cd extensions/vscode
pnpm install
pnpm run build
```

## Lint

```sh
pnpm run lint
```

## Test

```sh
pnpm run test
```

## Package

```sh
make vscode-vsix-package
```

The package artifact and SHA-256 sidecar are written under
`target/package/vscode/`.

## Scope

- `src/extension.ts` — extension activation and client lifecycle.
- `src/agentClient.ts` — metadata-only agent socket protocol client.
- The extension itself never writes audit rows directly.
