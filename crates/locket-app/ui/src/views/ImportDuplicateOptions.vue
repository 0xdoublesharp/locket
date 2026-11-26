<script setup lang="ts">
import { computed } from 'vue';
import type { DesktopImportEnvResponse, ImportDuplicateMatch } from '../agent/types';

const props = defineProps<{
  preview: DesktopImportEnvResponse;
  destinationIsShared: boolean;
  disabled: boolean;
  overriddenNames: string[];
}>();
type Choice = { kind: 'link' | 'promote'; target: string };
const selected = defineModel<Record<string, Choice>>({ required: true });

const matchesByName = computed(() => {
  const groups = new Map<string, ImportDuplicateMatch[]>();
  for (const match of props.preview.duplicate_matches) {
    const matches = groups.get(match.local_name) ?? [];
    matches.push(match);
    groups.set(match.local_name, matches);
  }
  return [...groups].map(([name, matches]) => ({
    name,
    matches,
    sharedNames: [
      ...new Set(
        matches.filter((match) => match.is_shared).map((match) => match.matched_secret_name),
      ),
    ],
  }));
});

function choose(name: string, choice: Choice, event: Event): void {
  const current = { ...selected.value };
  if ((event.target as HTMLInputElement).checked) current[name] = choice;
  else delete current[name];
  selected.value = current;
}
</script>

<template>
  <section class="import-matches" aria-label="Duplicate check results">
    <p v-if="!matchesByName.length" role="status">
      No matching duplicate values found. Check again with Global Vault unlocked.
    </p>
    <template v-else>
      <p role="status">
        Matching values found for {{ matchesByName.length }}
        {{ matchesByName.length === 1 ? 'key' : 'keys' }}.
      </p>
      <fieldset
        v-for="{ name, matches, sharedNames } in matchesByName"
        :key="name"
        :disabled="disabled"
      >
        <legend>
          <code>{{ name }}</code>
        </legend>
        <ul>
          <li v-for="match in matches" :key="match.matched_secret_id">
            {{ match.matched_project_name }} / {{ match.matched_profile_name }} /
            <code>{{ match.matched_secret_name }}</code>
          </li>
        </ul>
        <template v-if="!destinationIsShared">
          <p v-if="overriddenNames.includes(name)">
            A local override takes precedence over any link for this key.
          </p>
          <label v-for="target in overriddenNames.includes(name) ? [] : sharedNames" :key="target">
            <input
              type="checkbox"
              :checked="selected[name]?.kind === 'link' && selected[name]?.target === target"
              @change="choose(name, { kind: 'link', target }, $event)"
            />
            Link to <code>@shared/{{ target }}</code>
          </label>
          <label v-if="!sharedNames.length && !overriddenNames.includes(name)">
            <input
              type="checkbox"
              :checked="selected[name]?.kind === 'promote'"
              @change="choose(name, { kind: 'promote', target: name }, $event)"
            />
            Promote to <code>@shared/{{ name }}</code> &amp; link
          </label>
        </template>
      </fieldset>
    </template>
  </section>
</template>

<style scoped>
.import-matches,
.import-matches fieldset {
  display: grid;
  gap: 0.35rem;
  margin: 0;
  min-width: 0;
}
.import-matches fieldset {
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
}
.import-matches label {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.35rem;
}
.import-matches p {
  margin: 0;
}
.import-matches ul {
  margin: 0;
  padding-inline-start: 1.25rem;
  overflow-wrap: anywhere;
}
</style>
