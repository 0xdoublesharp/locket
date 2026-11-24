<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue';
import type { PaletteAction } from '../types/views';

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
const activeIndex = ref(0);
const results = computed(() => {
  const terms = query.value.trim().toLocaleLowerCase().split(/\s+/);
  return props.actions.filter((action) => {
    const text = [action.label, action.detail, action.keywords].join(' ').toLocaleLowerCase();
    return terms.every((term) => text.includes(term));
  });
});

watch(
  query,
  () => {
    activeIndex.value = 0;
  },
  { flush: 'sync' },
);
watch(results, () => {
  activeIndex.value = Math.max(0, Math.min(activeIndex.value, results.value.length - 1));
});

function syncDialog(): void {
  const element = dialog.value;
  if (!element) return;
  if (props.open && !element.open) {
    query.value = '';
    activeIndex.value = 0;
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
    if (current) run(current.id);
    return;
  }
  const length = results.value.length;
  if (!length || (event.key !== 'ArrowDown' && event.key !== 'ArrowUp')) return;
  event.preventDefault();
  const step = event.key === 'ArrowDown' ? 1 : -1;
  activeIndex.value = (activeIndex.value + step + length) % length;
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
      <button class="companion-button" type="button" @click="emit('update:open', false)">
        Close
      </button>
    </header>
    <input
      ref="searchInput"
      v-model="query"
      class="palette__search"
      type="text"
      role="combobox"
      aria-label="Search quick actions"
      aria-controls="palette-results"
      :aria-expanded="open"
      :aria-activedescendant="results.length ? `palette-result-${activeIndex}` : undefined"
      placeholder="Search projects, views, or variables"
      autocomplete="off"
      spellcheck="false"
    />
    <ul id="palette-results" class="palette__results" role="listbox" aria-label="Quick actions">
      <li
        v-for="(action, index) in results"
        :id="`palette-result-${index}`"
        :key="action.id"
        role="option"
        :aria-selected="index === activeIndex"
        @pointerenter="activeIndex = index"
        @click="run(action.id)"
      >
        <span>{{ action.label }}</span>
        <small v-if="action.detail">{{ action.detail }}</small>
      </li>
    </ul>
    <p v-if="results.length === 0" class="palette__empty" role="status">No matching actions.</p>
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
.palette__search {
  box-sizing: border-box;
  width: 100%;
  padding: 0.65rem;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  background: var(--bg-app);
  color: var(--text-primary);
  font: inherit;
}
.palette__results {
  max-height: min(46vh, 24rem);
  overflow: auto;
  margin: 0.5rem 0 0;
  padding: 0.125rem;
  list-style: none;
}
.palette__results li {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  justify-content: space-between;
  gap: 0.3rem 0.7rem;
  padding: 0.6rem;
  border-radius: var(--radius-sm);
  cursor: pointer;
  overflow-wrap: anywhere;
}
.palette__results li[aria-selected='true'] {
  color: var(--accent);
  background: var(--accent-soft);
}
.palette__results small,
.palette__empty {
  color: var(--text-secondary);
}
</style>
