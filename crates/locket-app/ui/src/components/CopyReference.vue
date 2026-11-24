<script setup lang="ts">
import { computed, onScopeDispose, ref, watch } from 'vue';
import { desktopCopyTextPlain } from '../agent/client';
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
    <button class="companion-button" type="button" @click.stop="copyReference">Copy lk://</button>
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
  font-size: 0.75rem;
  overflow-wrap: anywhere;
}
</style>
