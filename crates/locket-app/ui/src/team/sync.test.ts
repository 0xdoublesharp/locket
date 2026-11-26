import { describe, expect, it } from 'vitest';
import { joinCommand, syncMessage, validDeliveryUrl } from './sync';
describe('authenticated team sharing guidance', () => {
  it('requires an independent full pin and safely quotes folder paths', () => {
    expect(joinCommand('', 'a'.repeat(64))).toBeNull();
    expect(joinCommand('/team', 'short')).toBeNull();
    expect(joinCommand("/team's folder", 'a'.repeat(64), 'folder', 'posix')).toBe(
      `locket team join --folder '/team'"'"'s folder' --owner '${'a'.repeat(64)}'`,
    );
    expect(joinCommand('C:\\team & attacker.exe & rem', 'a'.repeat(64), 'folder', 'windows')).toBe(
      `locket team join --folder "C:\\team & attacker.exe & rem" --owner "${'a'.repeat(64)}"`,
    );
    expect(joinCommand('C:\\team\\%COMSPEC%', 'a'.repeat(64), 'folder', 'windows')).toBeNull();
    expect(joinCommand('C:\\team"bad', 'a'.repeat(64), 'folder', 'windows')).toBeNull();
  });
  it.each(['s3', 'webdav'] as const)('uses the configured %s delivery for remote joins', (kind) => {
    expect(joinCommand('', 'short', kind)).toBeNull();
    expect(joinCommand('', 'A'.repeat(64), kind)).toBe(
      `locket team join --remote --owner '${'a'.repeat(64)}'`,
    );
    expect(
      syncMessage({ state: 'verified', conflicts: 0, waiting: 0, transport_kind: kind }),
    ).toContain('Remote storage cannot prove');
  });
  it('rejects URLs with credentials and limits plain HTTP to local S3 endpoints', () => {
    expect(validDeliveryUrl('https://dav.example.test/team')).toBe(true);
    expect(validDeliveryUrl('http://localhost:9000', true)).toBe(true);
    expect(validDeliveryUrl('http://localhost:9000')).toBe(false);
    expect(validDeliveryUrl('http://minio.example.test', true)).toBe(false);
    expect(validDeliveryUrl('https://user:secret@dav.example.test/team')).toBe(false);
    expect(validDeliveryUrl('https://dav.example.test/team?token=secret')).toBe(false);
  });
  it('counts held profiles separately from conflicting values', () => {
    const message = syncMessage({
      state: 'pending-values',
      conflicts: 1,
      waiting: 0,
      pending_profiles: { prod: 'consent-required', preview: 'profile-name-collision' },
    });
    expect(message).toContain('2 profiles need');
    expect(message).toContain('1 value needs');
    expect(message).toContain('membership and key changes still apply');
    expect(
      syncMessage({
        state: 'pending-values',
        conflicts: 0,
        waiting: 0,
        pending_profiles: { prod: 'consent-required' },
      }),
    ).toContain('1 profile needs');
    expect(
      syncMessage({
        state: 'locked',
        conflicts: 1,
        waiting: 0,
        pending_profiles: { prod: 'consent-required' },
      }),
    ).toContain('Unlock');
  });
  it('never claims global freshness and makes blocked states actionable', () => {
    expect(syncMessage({ state: 'fork', conflicts: 0, waiting: 0 })).toContain('Stopped');
    expect(syncMessage({ state: 'locked', conflicts: 0, waiting: 2 })).toContain('Unlock');
    expect(syncMessage({ state: 'active', conflicts: 2, waiting: 0 })).toContain('2 values');
    expect(syncMessage({ state: 'active', conflicts: 0, waiting: 0 })).toContain('last verified');
  });
});
