<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue';
import type { PaletteAction, PaletteGroup } from '../types/views';
import { shortenProjectPath } from '../utils/projectPath';
import AppIcon from './AppIcon.vue';

const props = defineProps<{
  open: boolean;
  actions: PaletteAction[];
  blocked?: boolean;
}>();
const emit = defineEmits<{
  'update:open': [open: boolean];
  execute: [id: string];
}>();

const dialog = ref<HTMLDialogElement | null>(null);
const searchInput = ref<HTMLInputElement | null>(null);
const query = ref('');
const selectedIndex = ref<number | null>(null);
const groupOrder: PaletteGroup[] = ['Views', 'Quick actions', 'Projects', 'Variables', 'Actions'];
const groupId = (group: PaletteGroup) => `palette-group-${group.replaceAll(' ', '-')}`;
const groupedResults = computed(() => {
  const terms = query.value.trim().toLocaleLowerCase().split(/\s+/);
  const groups = new Map(groupOrder.map((group) => [group, [] as PaletteAction[]]));
  for (const action of props.actions) {
    const text = [action.label, action.detail, action.keywords, action.badge, action.group]
      .join(' ')
      .toLocaleLowerCase();
    if (terms.every((term) => text.includes(term)))
      groups.get(action.group ?? 'Actions')?.push(action);
  }
  let index = 0;
  return Array.from(groups, ([group, actions]) => ({
    group,
    items: actions.map((action) => ({ action, index: index++ })),
  })).filter(({ items }) => items.length);
});
const results = computed(() => groupedResults.value.flatMap(({ items }) => items));
const activeIndex = computed(
  () =>
    selectedIndex.value ??
    (query.value.trim()
      ? 0
      : results.value.findIndex(
          ({ action }) => action.group === 'Views' || action.group === 'Projects',
        )),
);

watch(
  query,
  () => {
    selectedIndex.value = null;
  },
  { flush: 'sync' },
);
watch(results, () => {
  if (selectedIndex.value !== null && selectedIndex.value >= results.value.length) {
    selectedIndex.value = null;
  }
});

function syncDialog(): void {
  const element = dialog.value;
  if (!element) return;
  if (props.open && !element.open) {
    query.value = '';
    selectedIndex.value = null;
    element.showModal();
    searchInput.value?.focus();
  } else if (!props.open && element.open) {
    element.close();
  }
}

function globalShortcut(event: KeyboardEvent): void {
  if (
    event.defaultPrevented ||
    event.repeat ||
    event.isComposing ||
    !(event.metaKey || event.ctrlKey) ||
    event.altKey ||
    event.shiftKey ||
    event.key.toLowerCase() !== 'k' ||
    (!props.open && (props.blocked || document.querySelector('[aria-modal="true"], dialog[open]')))
  )
    return;
  event.preventDefault();
  emit('update:open', !props.open);
}

onMounted(() => {
  syncDialog();
  window.addEventListener('keydown', globalShortcut);
});
onUnmounted(() => window.removeEventListener('keydown', globalShortcut));
watch(() => props.open, syncDialog, { flush: 'post' });

function run(id: string): void {
  emit('update:open', false);
  emit('execute', id);
}

function onKeys(event: KeyboardEvent): void {
  if (event.isComposing) return;
  if (event.key === 'Escape') {
    event.preventDefault();
    emit('update:open', false);
    return;
  }
  if (event.key === 'Enter' && event.target === searchInput.value) {
    event.preventDefault();
    const current = results.value[activeIndex.value];
    if (current) run(current.action.id);
    return;
  }
  const length = results.value.length;
  if (!length || (event.key !== 'ArrowDown' && event.key !== 'ArrowUp')) return;
  event.preventDefault();
  const step = event.key === 'ArrowDown' ? 1 : -1;
  const previous = activeIndex.value < 0 && step < 0 ? 0 : activeIndex.value;
  selectedIndex.value = (previous + step + length) % length;
  void nextTick(() => {
    document
      .getElementById(`palette-result-${activeIndex.value}`)
      ?.scrollIntoView({ block: 'nearest' });
  });
}
</script>

<template>
  <dialog
    ref="dialog"
    class="palette"
    aria-labelledby="palette-title"
    @keydown="onKeys"
    @cancel.prevent="emit('update:open', false)"
  >
    <header class="palette__header">
      <h2 id="palette-title">Quick actions</h2>
      <button
        class="companion-button icon-label"
        type="button"
        aria-label="Close"
        @click="emit('update:open', false)"
      >
        <AppIcon name="x" />
      </button>
    </header>
    <div class="palette__field">
      <AppIcon name="search" :size="20" />
      <input
        ref="searchInput"
        v-model="query"
        class="palette__search"
        type="text"
        role="combobox"
        aria-label="Search quick actions"
        aria-controls="palette-results"
        :aria-expanded="open"
        :aria-activedescendant="
          results.length && activeIndex >= 0 ? `palette-result-${activeIndex}` : undefined
        "
        placeholder="Search projects, views, or variables"
        autocomplete="off"
        spellcheck="false"
      />
    </div>
    <div id="palette-results" class="palette__results" role="listbox" aria-label="Quick actions">
      <div
        v-for="{ group, items } in groupedResults"
        :key="group"
        role="group"
        :aria-labelledby="groupId(group)"
      >
        <h3 :id="groupId(group)">{{ group }}</h3>
        <div
          v-for="{ action, index } in items"
          :id="`palette-result-${index}`"
          :key="action.id"
          class="palette__result"
          role="option"
          :aria-selected="index === activeIndex"
          @pointermove="selectedIndex = index"
          @click="run(action.id)"
        >
          <AppIcon :name="action.icon ?? 'compass'" />
          <div>
            <span :title="action.label">{{ action.label }}</span>
            <small v-if="action.detail" :title="action.detail">
              {{ group === 'Projects' ? shortenProjectPath(action.detail) : action.detail }}
            </small>
          </div>
          <span class="palette__badge">{{ action.badge ?? 'Action' }}</span>
        </div>
      </div>
      <p v-if="results.length === 0" class="palette__empty" role="status">No matching actions.</p>
    </div>
    <footer class="palette__footer">
      <span><kbd>↑↓</kbd> Navigate</span>
      <span><kbd>↵</kbd> Select</span>
      <span><kbd>Esc</kbd> Close</span>
    </footer>
  </dialog>
</template>

<style scoped>
.palette {
  position: fixed;
  inset: min(12vh, 6rem) 0 auto;
  box-sizing: border-box;
  width: min(36rem, calc(100% - 1.5rem));
  max-height: 80vh;
  padding: 0.85rem;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-lg);
  background: var(--bg-elevated);
  color: var(--text-primary);
  box-shadow: var(--shadow-lg);
}

.palette::backdrop {
  background: var(--backdrop);
}

.palette__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
}
.palette__header h2 {
  margin: 0;
  font-size: 1rem;
}
.palette__field {
  position: relative;
  color: var(--text-secondary);
}
.palette__field > .app-icon {
  position: absolute;
  left: 0.65rem;
  top: 50%;
  transform: translateY(-50%);
  pointer-events: none;
}
.palette__search {
  box-sizing: border-box;
  width: 100%;
  padding: 0.65rem 0.65rem 0.65rem 2.35rem;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  background: var(--bg-app);
  color: var(--text-primary);
  font: inherit;
  font-size: 0.875rem;
}
.palette__results {
  max-height: min(57vh, 31rem);
  overflow: auto;
  margin-top: 0.45rem;
  padding: 0.1rem 0.1rem 0.7rem;
  scroll-padding-block: 0.45rem 0.7rem;
  scrollbar-gutter: stable;
}
.palette__results::after {
  position: sticky;
  bottom: -0.7rem;
  display: block;
  height: 0.55rem;
  margin-bottom: -0.55rem;
  background: linear-gradient(transparent, var(--bg-elevated));
  content: '';
  pointer-events: none;
}
.palette__results h3 {
  margin: 0.6rem 0.45rem 0.3rem;
  color: var(--text-secondary);
  font-size: 0.75rem;
  font-weight: 650;
}
.palette__result {
  box-sizing: border-box;
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: center;
  gap: 0.55rem;
  min-height: 2.125rem;
  padding: 0.3rem 0.45rem;
  border-radius: var(--radius-sm);
  font-size: 0.875rem;
  cursor: pointer;
}
.palette__result[aria-selected='true'] {
  color: var(--accent);
  background: var(--accent-soft);
}
.palette__result div > *,
.palette__badge {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.palette__badge {
  padding: 0.125rem 0.35rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  background: var(--bg-surface);
  color: var(--text-secondary);
  font-size: 0.68rem;
}
.palette__results small,
.palette__empty,
.palette__footer {
  color: var(--text-secondary);
}
.palette__results small {
  margin-top: 0.15rem;
  font: 0.72rem var(--font-mono);
}
.palette__footer {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem 0.9rem;
  padding-top: 0.6rem;
  margin-top: 0.5rem;
  border-top: 1px solid var(--border-subtle);
  font-size: 0.75rem;
}
.palette__footer kbd {
  color: var(--text-primary);
}
</style>
