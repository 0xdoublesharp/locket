<script setup lang="ts">
import { computed } from 'vue';
import AppIcon from './AppIcon.vue';

const props = defineProps<{ source: string }>();
const badge = computed(() => {
  switch (props.source) {
    case 'team-managed':
    case 'team':
      return { label: 'Shared', icon: 'cloud', tone: 'shared' } as const;
    case 'shared-link':
      return { label: 'Shared link', icon: 'link', tone: 'linked' } as const;
    case 'user-local':
      return { label: 'My override', icon: 'user', tone: 'override' } as const;
    case 'machine-local':
      return { label: 'This machine', icon: 'laptop', tone: 'local' } as const;
    default:
      return null;
  }
});
</script>

<template>
  <span v-if="badge" class="source-badge" :data-tone="badge.tone">
    <AppIcon :name="badge.icon" :size="14" />
    {{ badge.label }}
  </span>
  <span v-else>{{ source }}</span>
</template>

<style scoped>
.source-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.15rem 0.4rem;
  border-radius: var(--radius-sm);
  background: var(--bg-subtle);
  color: var(--text-secondary);
  font-size: 0.7rem;
  white-space: nowrap;
}
.source-badge[data-tone='shared'] {
  color: var(--info);
  background: var(--info-soft);
}
.source-badge[data-tone='linked'] {
  color: var(--accent);
  background: var(--accent-soft);
}
.source-badge[data-tone='override'] {
  color: var(--success);
  background: var(--success-soft);
}
</style>
