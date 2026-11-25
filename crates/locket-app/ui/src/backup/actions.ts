export type ExportScope = 'active-profile' | 'all-profiles';
export type ConflictMode = 'review' | 'accept-incoming' | 'accept-local';
export type RecoveryVerification = 'platform' | 'current-code';

export interface ExportDraft {
  recipientDescriptor: string;
  scope: ExportScope;
  includeAudit: boolean;
  includePersonal: boolean;
  includeHistory: boolean;
  confirmDangerousProfile: string;
  previewOnly: boolean;
  outputPath: string;
}

export interface ImportDraft {
  bundlePath: string;
  includeAudit: boolean;
  conflictMode: ConflictMode;
  confirmDangerousProfile: string;
}

export interface VerifyDraft {
  bundlePath: string;
  requireDecryptable: boolean;
}

export interface RotateDraft {
  verification: RecoveryVerification;
  acknowledgedOneTimeDisplay: boolean;
  clearAfterDisplay: boolean;
}

export type BundleAction =
  | {
      kind: 'export';
      label: string;
      request: ExportDraft;
    }
  | {
      kind: 'import';
      label: string;
      request: ImportDraft;
    }
  | {
      kind: 'verify';
      label: string;
      request: VerifyDraft;
    }
  | {
      kind: 'rotate';
      label: string;
      request: RotateDraft;
    };

export function exportSelectionKey(draft: ExportDraft): string {
  return JSON.stringify([
    draft.recipientDescriptor,
    draft.scope,
    draft.includeAudit,
    draft.includePersonal,
    draft.includeHistory,
    draft.outputPath,
  ]);
}
