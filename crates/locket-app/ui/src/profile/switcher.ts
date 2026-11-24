// Pure model for the profile-switcher view.
//
// Owns the rules around which profiles are listed, which entries are
// flagged dangerous, and whether a switch attempt requires typed
// confirmation. Living outside Vue keeps the behaviour unit-testable.

export interface ProfileEntry {
  /** Profile name (free-form). Used as the unique key. */
  name: string;
  /** Whether the agent has flagged this profile as dangerous. */
  dangerous: boolean;
}

export interface ProfileSwitchState {
  /** Active profile name reported by the agent, if any. */
  activeProfile: string | null;
  /** Whether the active profile is currently flagged dangerous. */
  activeDangerous: boolean;
  /** Local cache of recently used target profile names. */
  recentTargets: string[];
  knownProfiles?: ProfileEntry[];
}

/** Build the renderable entry list. Active profile is always first. */
export function profileEntries(state: ProfileSwitchState): ProfileEntry[] {
  const seen = new Set<string>();
  const out: ProfileEntry[] = [];
  if (state.activeProfile !== null && state.activeProfile.length > 0) {
    out.push({ name: state.activeProfile, dangerous: state.activeDangerous });
    seen.add(state.activeProfile);
  }
  for (const entry of state.knownProfiles ?? []) {
    if (!entry.name || seen.has(entry.name)) continue;
    out.push(entry);
    seen.add(entry.name);
  }
  for (const target of state.recentTargets) {
    if (target.length === 0 || seen.has(target)) {
      continue;
    }
    seen.add(target);
    out.push({ name: target, dangerous: false });
  }
  return out;
}

/**
 * Whether a switch from the active profile to `target` requires the
 * user to type the target's name. The desktop spec gates dangerous
 * switches; we treat a switch *into* a dangerous profile as the
 * dangerous direction. Switching *away from* a dangerous profile is
 * safer but still goes through the agent's own gate.
 */
export function profileSwitchRequiresTypedConfirmation(
  target: string,
  targetDangerous: boolean,
): boolean {
  if (target.length === 0) {
    return false;
  }
  return targetDangerous;
}

/** Whether a target profile name is well-formed enough to submit. */
export function isValidProfileName(name: string): boolean {
  const trimmed = name.trim();
  if (trimmed.length === 0 || trimmed.length > 128) {
    return false;
  }
  return /^[A-Za-z0-9._-]+$/.test(trimmed);
}

/** Append a freshly-used target to the recent list (deduped, MRU first). */
export function rememberTarget(state: ProfileSwitchState, target: string): ProfileSwitchState {
  const trimmed = target.trim();
  if (trimmed.length === 0) {
    return state;
  }
  const filtered = state.recentTargets.filter((name) => name !== trimmed);
  return { ...state, recentTargets: [trimmed, ...filtered].slice(0, 8) };
}
