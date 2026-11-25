import { describe, expect, it } from 'vitest';
import { exportSelectionKey, type ExportDraft } from './actions';
const draft: ExportDraft = {
  recipientDescriptor: 'fixture-recipient',
  scope: 'active-profile',
  includeAudit: false,
  includePersonal: false,
  includeHistory: false,
  confirmDangerousProfile: '',
  outputPath: '',
  previewOnly: true,
};
describe('backup scope preview', () => {
  it('allows the same selection to export after preview', () => {
    expect(exportSelectionKey(draft)).toBe(exportSelectionKey({ ...draft, previewOnly: false }));
  });
  it('lets the user confirm the previewed selection without changing its scope', () => {
    expect(exportSelectionKey(draft)).toBe(
      exportSelectionKey({ ...draft, confirmDangerousProfile: 'dev' }),
    );
  });
  it.each([
    'recipientDescriptor',
    'scope',
    'includeAudit',
    'includePersonal',
    'includeHistory',
    'outputPath',
  ] as const)('invalidates preview after changing %s', (field) => {
    expect(exportSelectionKey(draft)).not.toBe(
      exportSelectionKey({
        ...draft,
        [field]: typeof draft[field] === 'boolean' ? true : 'changed',
      } as ExportDraft),
    );
  });
});
