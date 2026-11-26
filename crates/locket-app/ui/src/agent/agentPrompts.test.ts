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
  it('guides an approved migration from remaining-file inventory through safe archiving', () => {
    const prompt = dotenvMigrationPrompt();
    for (const instruction of [
      'NEVER read raw .env file contents directly',
      'locket env scan --remaining --json',
      'locket_scan_env_files',
      'If the metadata-only scan or preview options are unavailable, stop',
    ]) {
      expect(prompt).toContain(instruction);
    }
    const steps = prompt.split('\n\n').filter((paragraph) => /^\d\. /.test(paragraph));
    expect(steps).toEqual([
      expect.stringContaining('by key name and migration status'),
      expect.stringContaining('locket shared list'),
      expect.stringContaining('locket import <file> --dry-run --json'),
      expect.stringContaining('locket unlock --project <project1> --project <project2> --ttl 3600'),
      expect.stringContaining(
        'locket import <file> --archive <DIR> --archive-if-matching [--verify-policy <POLICY>] --dry-run --json',
      ),
    ]);
    expect(steps[1]).toContain('locket import <file> --keep');
    expect(steps[2]).toContain('locket init');
    expect(steps[2]).toContain('locket_import_env');
    expect(steps[2]).toContain('locket policy detect');
    expect(steps[2]).toContain('locket policy add');
    expect(steps[2]).toContain('wait for my approval');
    expect(steps[3]).toContain('locket run <policy>');
    expect(steps[3]).toContain('locket exec');
    expect(steps[4]).toContain('archive_consumer_warnings');
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
