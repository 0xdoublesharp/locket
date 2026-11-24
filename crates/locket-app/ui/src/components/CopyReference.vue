<script setup lang="ts">
import { computed, onScopeDispose, ref, watch } from 'vue';
import { desktopCopyTextPlain } from '../agent/client';
import AppIcon from './AppIcon.vue';
import { createRequestLifetime } from '../utils/requestLifetime';

const props = defineProps<{ reference: string | null }>();
const copiedReference = ref<string | null>(null);
const failedReference = ref<string | null>(null);
const requests = createRequestLifetime();
watch(
  () => props.reference,
  () => {
    requests.invalidate();
    copiedReference.value = null;
    failedReference.value = null;
  },
  { flush: 'sync' },
);
onScopeDispose(requests.dispose);
const message = computed(() => {
  if (!props.reference) return '';
  if (copiedReference.value === props.reference) return `Copied ${props.reference}`;
  if (failedReference.value === props.reference) return 'Could not copy reference.';
  return '';
});

async function copyReference(): Promise<void> {
  const reference = props.reference;
  if (!reference) return;
  copiedReference.value = null;
  failedReference.value = null;
  const isCurrent = requests.begin();
  const result = await desktopCopyTextPlain(reference);
  if (!isCurrent()) return;
  if (result.ok) copiedReference.value = reference;
  else failedReference.value = reference;
}
</script>

<template>
  <span v-if="reference" class="copy-reference">
    <button
      class="companion-button icon-label"
      type="button"
      :title="message || 'Copy variable reference'"
      @click.stop="copyReference"
    >
      <AppIcon :name="copiedReference ? 'check' : failedReference ? 'alert' : 'link'" />
      Copy ref
    </button>
    <span v-if="message" role="status">{{ message }}</span>
  </span>
</template>

<style scoped>
.copy-reference {
  display: inline-flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.35rem;
}
.copy-reference span {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  overflow: hidden;
  clip-path: inset(50%);
  white-space: nowrap;
}
</style>
