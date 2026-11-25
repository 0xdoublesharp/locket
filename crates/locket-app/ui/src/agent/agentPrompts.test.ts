import { describe, expect, it } from 'vitest';
import { dotenvMigrationPrompt, mcpClientSnippets } from './agentPrompts';

describe('mcpClientSnippets', () => {
  it('generates copy-ready JSON and commands for a CLI on PATH', () => {
    const snippets = mcpClientSnippets('locket', ['mcp']);
    expect(JSON.parse(snippets.json)).toEqual({
      mcpServers: { locket: { command: 'locket', args: ['mcp'] } },
    });
    expect(snippets.claude).toBe('claude mcp add locket -- locket mcp');
    expect(snippets.codex).toBe('codex mcp add locket -- locket mcp');
  });

  it('quotes shell metacharacters, paths with spaces, and empty arguments', () => {
    const command = "/Applications/Justin's Locket.app/locket";
    const args = ['mcp', '--label', '$HOME; echo text', ''];
    const snippets = mcpClientSnippets(command, args);
    const launch =
      "'/Applications/Justin'\\''s Locket.app/locket' mcp --label '$HOME; echo text' ''";
    expect(JSON.parse(snippets.json).mcpServers.locket).toEqual({ command, args });
    expect(snippets.claude).toBe(`claude mcp add locket -- ${launch}`);
    expect(snippets.codex).toBe(`codex mcp add locket -- ${launch}`);
  });
});

describe('dotenvMigrationPrompt', () => {
  it('specifies a metadata-only scan, approval, and a non-destructive split import', () => {
    const prompt = dotenvMigrationPrompt();
    for (const instruction of [
      'NEVER read raw .env file contents directly',
      'locket env scan --json',
      'locket_scan_env_files',
      'shared_candidates',
      'locket import <file> --dry-run --json',
      'wait for my approval before writing',
      'locket import <file> --project @shared --only <keys> --keep --json',
      'locket import <file> --exclude <keys> --keep --json',
      'locket_import_env',
      'Keep the original .env files through verification',
      'If the metadata-only scan or preview options are unavailable, stop',
    ]) {
      expect(prompt).toContain(instruction);
    }
  });

  it('adds vault context without changing the migration steps', () => {
    expect(dotenvMigrationPrompt()).not.toContain('The active vault');
    expect(dotenvMigrationPrompt({ vaultName: '  Demo App  ' })).toContain(
      'The active vault label is "Demo App".',
    );
    expect(dotenvMigrationPrompt({ isShared: true, vaultName: 'ignored' })).toContain(
      'The active vault is Global Vault (@shared).',
    );
  });
});
