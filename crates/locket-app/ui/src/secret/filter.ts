// Pure metadata-only filter helpers for the desktop secret list.
//
// Lives outside the Vue runtime so the predicate logic is unit-testable
// without spinning up jsdom. The Vue view (`SecretMetadataList.vue`)
// mirrors UI state into `SecretFilterState` and applies
// `filterSecretRows` against the already-loaded metadata list. The
// filter never inspects values; only metadata fields the view already
// holds.

import type { SecretRowMeta } from '../types/views';

export type SecretSourceFilter = 'all' | SecretRowMeta['source'];
export type SecretRequiredFilter = 'all' | 'required' | 'optional';
export type SecretDeprecationFilter = 'all' | 'deprecated' | 'current';

export interface SecretFilterState {
  source: SecretSourceFilter;
  required: SecretRequiredFilter;
  deprecation: SecretDeprecationFilter;
}

export function defaultSecretFilter(): SecretFilterState {
  return { source: 'all', required: 'all', deprecation: 'all' };
}

export function filterSecretRows(
  rows: ReadonlyArray<SecretRowMeta>,
  state: SecretFilterState,
): SecretRowMeta[] {
  return rows.filter((row) => matchesFilter(row, state));
}

function matchesFilter(row: SecretRowMeta, state: SecretFilterState): boolean {
  if (state.source !== 'all' && row.source !== state.source) {
    return false;
  }
  switch (state.required) {
    case 'required':
      if (!row.required) {
        return false;
      }
      break;
    case 'optional':
      if (row.required) {
        return false;
      }
      break;
    default:
      break;
  }
  switch (state.deprecation) {
    case 'deprecated':
      if (!row.hasDeprecatedGrace) {
        return false;
      }
      break;
    case 'current':
      if (row.hasDeprecatedGrace) {
        return false;
      }
      break;
    default:
      break;
  }
  return true;
}

/** Whether any non-default filter is currently applied. */
export function isSecretFilterActive(state: SecretFilterState): boolean {
  return state.source !== 'all' || state.required !== 'all' || state.deprecation !== 'all';
}
