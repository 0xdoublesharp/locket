// Tests for the desktop secret editor form models.
//
// Tests run under vitest. When the runner is not configured locally,
// the file is skipped at collection time. The assertions below are
// hand-verifiable for code review.

import { describe, expect, it } from 'vitest';

import {
  defaultDeleteForm,
  defaultRotateForm,
  defaultSetForm,
  deleteFormToRequest,
  rotateFormToPayload,
  setFormToPayload,
  validateDeleteForm,
  validateRotateForm,
  validateSetForm,
} from './editor';

const PROJECT_ID = 'project-1';
const PROFILE_ID = 'profile-1';

describe('imported portable secret names', () => {
  it('allows underscore-prefixed names through create, rotate, and delete', () => {
    const name = '_SERVICE_2';
    expect(validateSetForm({ ...defaultSetForm(), name, value: 'initial' }).valid).toBe(true);
    expect(validateRotateForm({ ...defaultRotateForm(), name, value: 'rotated' }).valid).toBe(true);
    expect(validateDeleteForm({ ...defaultDeleteForm(), name, confirmation: name }).valid).toBe(
      true,
    );
  });
});

describe('validateSetForm', () => {
  it('accepts a typical KEY value pair', () => {
    const result = validateSetForm({
      ...defaultSetForm(),
      name: 'DATABASE_URL',
      value: 'postgres://user:pw@host:5432/db',
      description: 'Primary DB',
      source: 'team-managed',
    });
    expect(result.valid).toBe(true);
  });

  it('rejects a name that does not start with A-Z', () => {
    const result = validateSetForm({
      ...defaultSetForm(),
      name: '1MIXED_CASE',
      value: 'x',
    });
    expect(result.valid).toBe(false);
    expect(result.errors.name).toMatch(/KEY_FORMAT/);
  });

  it('rejects an empty value', () => {
    const result = validateSetForm({ ...defaultSetForm(), name: 'X', value: '' });
    expect(result.valid).toBe(false);
    expect(result.errors.value).toMatch(/required/);
  });

  it('rejects a value containing a NUL byte', () => {
    const result = validateSetForm({
      ...defaultSetForm(),
      name: 'X',
      value: 'before\0after',
    });
    expect(result.valid).toBe(false);
    expect(result.errors.value).toMatch(/NUL/);
  });
});

describe('setFormToPayload', () => {
  it('forwards the form fields and trims the name', () => {
    const payload = setFormToPayload(
      { ...defaultSetForm(), name: ' AWS_ACCESS_KEY_ID ', value: 'abc', source: 'machine-local' },
      { projectId: PROJECT_ID, profileId: PROFILE_ID, grantId: 'grant-1' },
    );
    expect(payload).toEqual({
      project_id: PROJECT_ID,
      profile_id: PROFILE_ID,
      grant_id: 'grant-1',
      secret_name: 'AWS_ACCESS_KEY_ID',
      value: 'abc',
      source: 'machine-local',
    });
  });
});

describe('validateRotateForm', () => {
  it('accepts a future grace expiry', () => {
    const future = new Date(Date.now() + 86_400_000).toISOString();
    const result = validateRotateForm({
      ...defaultRotateForm(),
      name: 'X',
      value: 'new',
      graceUntil: future,
    });
    expect(result.valid).toBe(true);
  });

  it('rejects past grace expiry', () => {
    const past = new Date(Date.now() - 86_400_000).toISOString();
    const result = validateRotateForm({
      ...defaultRotateForm(),
      name: 'X',
      value: 'new',
      graceUntil: past,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.graceUntil).toMatch(/future/);
  });
});

describe('rotateFormToPayload', () => {
  it('omits grace_until when blank and includes grant context', () => {
    const payload = rotateFormToPayload(
      { name: 'TOKEN', value: 'fresh', graceUntil: '' },
      { projectId: PROJECT_ID, profileId: PROFILE_ID, source: 'user-local', grantId: 'g-2' },
    );
    expect(payload.secret_name).toBe('TOKEN');
    expect(payload.grace_until).toBeUndefined();
    expect(payload.source).toBe('user-local');
    expect(payload.grant_id).toBe('g-2');
  });

  it('converts grace_until to nanoseconds', () => {
    const future = new Date(Date.now() + 86_400_000).toISOString();
    const payload = rotateFormToPayload(
      { name: 'TOKEN', value: 'fresh', graceUntil: future },
      { projectId: PROJECT_ID, profileId: PROFILE_ID, source: 'user-local' },
    );
    expect(typeof payload.grace_until).toBe('number');
    expect(payload.grace_until).toBeGreaterThan(Date.now() * 1_000_000);
  });
});

describe('validateDeleteForm', () => {
  it('requires the typed confirmation to match', () => {
    expect(
      validateDeleteForm({ ...defaultDeleteForm(), name: 'TOKEN', confirmation: '' }).valid,
    ).toBe(false);
    expect(
      validateDeleteForm({ ...defaultDeleteForm(), name: 'TOKEN', confirmation: 'TOKE' }).valid,
    ).toBe(false);
    expect(
      validateDeleteForm({ ...defaultDeleteForm(), name: 'TOKEN', confirmation: 'TOKEN' }).valid,
    ).toBe(true);
  });
});

describe('deleteFormToRequest', () => {
  it('echoes the typed confirmation in the wire request', () => {
    expect(
      deleteFormToRequest(
        { name: 'TOKEN', confirmation: 'TOKEN' },
        { projectId: PROJECT_ID, profileId: PROFILE_ID },
      ),
    ).toEqual({
      project_id: PROJECT_ID,
      profile_id: PROFILE_ID,
      secret_name: 'TOKEN',
      typed_confirmation: 'TOKEN',
    });
  });
});

describe('defaults', () => {
  it('produce stable starting values', () => {
    expect(defaultSetForm().source).toBe('user-local');
    expect(defaultRotateForm().graceUntil).toBe('');
    expect(defaultDeleteForm().confirmation).toBe('');
  });
});
