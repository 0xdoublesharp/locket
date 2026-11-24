<script setup lang="ts">
import { ref } from 'vue';
import { desktopActionsAvailable, desktopPickDirectory, desktopPickFile } from '../agent/client';

const props = defineProps<{
  title: string;
  directory?: boolean;
  save?: boolean;
  defaultName?: string;
  disabled?: boolean;
}>();
const emit = defineEmits<{ pick: [path: string] }>();
const pending = ref(false);
const error = ref(false);

async function browse(): Promise<void> {
  pending.value = true;
  error.value = false;
  const result = props.directory
    ? await desktopPickDirectory(props.title)
    : await desktopPickFile({
        title: props.title,
        save: props.save ?? false,
        ...(props.defaultName && { defaultName: props.defaultName }),
      });
  if (result.ok) {
    if (result.value !== null) emit('pick', result.value);
  } else {
    error.value = true;
  }
  pending.value = false;
}
</script>

<template>
  <button
    class="companion-button"
    type="button"
    :aria-label="title"
    :disabled="disabled || pending || !desktopActionsAvailable()"
    @click="browse"
  >
    Browse…
  </button>
  <small v-if="error" role="status">Could not open the picker. Enter a path manually.</small>
</template>
