import { describe, expect, it, vi } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import { findNode, mountComponent, settle } from '../test/renderer';
import CopyReference from '../components/CopyReference.vue';
import { secretReference } from './reference';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: () => true }));

describe('variable references', () => {
  it('uses the environment name and variable key with no value material', () => {
    expect(secretReference('staging', 'DATABASE_URL', false)).toBe('lk://staging/DATABASE_URL');
    expect(secretReference('default', 'POSTMARK_TOKEN', false)).toBe('lk://default/POSTMARK_TOKEN');
    expect(secretReference('prod', 'JWT_SIGNING_KEY', true)).toBeNull();
    expect(secretReference(null, 'JWT_SIGNING_KEY', false)).toBeNull();
  });

  it('copies only the reference through the metadata clipboard and confirms inline', async () => {
    const reference = secretReference('dev', 'DATABASE_URL', false);
    const view = mountComponent(CopyReference, { reference });
    try {
      const button = findNode(view.root, (node) => node.tag === 'button');
      (button!.props.onClick as (event: { stopPropagation: () => void }) => void)({
        stopPropagation: () => {},
      });
      await settle();
      expect(invoke).toHaveBeenCalledExactlyOnceWith('desktop_copy_text_plain', {
        text: reference,
      });
      expect(findNode(view.root, (node) => node.props.role === 'status')?.text).toBe(
        'Copied lk://dev/DATABASE_URL',
      );
    } finally {
      view.unmount();
    }
  });
});
