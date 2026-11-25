<script setup lang="ts">
import type { AppIconName } from '../types/views';

defineProps<{ name: AppIconName; size?: number }>();
</script>

<template>
  <svg
    class="app-icon"
    :width="size ?? 16"
    :height="size ?? 16"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="1.7"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
    focusable="false"
  >
    <template v-if="name === 'brand-lock'">
      <defs>
        <linearGradient
          id="locket-brand-ring"
          x1="2"
          y1="2"
          x2="22"
          y2="22"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stop-color="#36d2d5" />
          <stop offset="35%" stop-color="#6756d9" />
          <stop offset="70%" stop-color="#ff6255" />
          <stop offset="100%" stop-color="#a8db55" />
        </linearGradient>
      </defs>
      <rect
        x="1"
        y="1"
        width="22"
        height="22"
        rx="6"
        fill="#111b23"
        stroke="url(#locket-brand-ring)"
        stroke-width="1.25"
      />
      <path d="M9.2 10.6V8.3a2.8 2.8 0 0 1 5.6 0v2.3" stroke="#f6d577" stroke-width="1.6" />
      <rect
        x="6.75"
        y="10.6"
        width="10.5"
        height="7.6"
        rx="2"
        fill="#111b23"
        stroke="#f6d577"
        stroke-width="1.5"
      />
      <path
        d="M12 14.4 9.7 12.1 12 13.1l2.3-1-2.3 2.3 2.3 2.3-2.3-1-2.3 1z"
        fill="#f7fafb"
        stroke="none"
      />
    </template>
    <template v-else-if="name === 'lock' || name === 'unlock'">
      <rect x="5" y="10" width="14" height="11" rx="2.5" />
      <path v-if="name === 'lock'" d="M8 10V7a4 4 0 1 1 8 0v3" />
      <path v-else d="M8 10V7a4 4 0 0 1 7.7-1.5" />
      <path d="M12 14.5v2" />
    </template>
    <path
      v-else-if="name === 'folder'"
      d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"
    />
    <path
      v-else-if="name === 'key'"
      d="M14.5 4a5.5 5.5 0 0 0-5.1 7.55L3 18v3h3v-2.5h2.5V16l3.95-3.4A5.5 5.5 0 1 0 14.5 4ZM15.7 8h.1"
    />
    <template v-else-if="name === 'terminal'">
      <rect x="2.5" y="4.5" width="19" height="15" rx="3" />
      <path d="m6.5 9 3 3-3 3m6 0h4" />
    </template>
    <path v-else-if="name === 'activity'" d="M2.5 12h4l3-7 4.5 14 3-7h4.5" />
    <template v-else-if="name === 'users'">
      <circle cx="9" cy="8" r="3" />
      <path
        d="M2.5 19v-1.5A3.5 3.5 0 0 1 6 14h6a3.5 3.5 0 0 1 3.5 3.5V19M16 5a3 3 0 0 1 0 6m2 3a3.5 3.5 0 0 1 3.5 3.5V19"
      />
    </template>
    <template v-else-if="name === 'settings'">
      <path
        d="m10 3-.6 2.5-1.7 1L5.2 6l-2 3.5L5 11.2v1.6L3.2 14.5l2 3.5 2.5-.5 1.7 1L10 21h4l.6-2.5 1.7-1 2.5.5 2-3.5-1.8-1.7v-1.6l1.8-1.7-2-3.5-2.5.5-1.7-1L14 3z"
      />
      <circle cx="12" cy="12" r="3" />
    </template>
    <template v-else-if="name === 'search'">
      <circle cx="10.5" cy="10.5" r="5.75" />
      <path d="m15 15 4.25 4.25" />
    </template>
    <template v-else-if="name === 'copy'">
      <rect x="8" y="8" width="12" height="13" rx="2" />
      <path d="M15.5 5.5V5a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2" />
    </template>
    <path
      v-else-if="name === 'link'"
      d="m10 7 2.8-2.8a4.25 4.25 0 0 1 6 6L16 13m-2 4-2.8 2.8a4.25 4.25 0 0 1-6-6L8 11m1.5 3.5 5-5"
    />
    <template v-else-if="name === 'eye'">
      <path d="M2.5 12S5.8 6 12 6s9.5 6 9.5 6-3.3 6-9.5 6S2.5 12 2.5 12Z" />
      <circle cx="12" cy="12" r="2.5" />
    </template>
    <template v-else-if="name === 'clock'">
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3 2" />
    </template>
    <path
      v-else-if="name === 'fingerprint'"
      d="M4 12a8 8 0 1 1 16 0v2m-13.5 3.5A14 14 0 0 0 7 12a5 5 0 0 1 10 0c0 3-.5 5.5-1.5 7.5M9 20a17 17 0 0 0 1-8 2 2 0 1 1 4 0c0 4-.8 7-2 9"
    />
    <path
      v-else-if="name === 'refresh'"
      d="M20 10a8 8 0 0 0-13.7-4.3L4 8m0-4v4h4m-4 6a8 8 0 0 0 13.7 4.3L20 16m-4 0h4v4"
    />
    <template v-else-if="name === 'info'">
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 8h.01m-.01 3.5V16" />
    </template>
    <template v-else-if="name === 'alert'">
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 8v4.5m0 3.5h.01" />
    </template>
    <path v-else-if="name === 'check'" d="m5.5 12 4 4 9-9" />
    <path v-else-if="name === 'plus'" d="M12 5v14M5 12h14" />
    <path
      v-else-if="name === 'cloud'"
      d="M6.5 18a4.5 4.5 0 0 1-.6-8.96 6 6 0 0 1 11.45-1.5A5.25 5.25 0 0 1 17 18Z"
    />
    <template v-else-if="name === 'user'">
      <circle cx="12" cy="8" r="3.25" />
      <path d="M5.5 20v-2a4 4 0 0 1 4-4h5a4 4 0 0 1 4 4v2" />
    </template>
    <path
      v-else-if="name === 'laptop'"
      d="M5 16V6.5A1.5 1.5 0 0 1 6.5 5h11A1.5 1.5 0 0 1 19 6.5V16m-14 0h14l2 2v1H3v-1z"
    />
    <template v-else-if="name === 'compass'">
      <circle cx="12" cy="12" r="8.5" />
      <path d="m15.5 8.5-2 5-5 2 2-5z" />
    </template>
    <path v-else-if="name === 'chevron-down'" d="m6.5 9.5 5.5 5 5.5-5" />
    <path v-else-if="name === 'x'" d="m6 6 12 12M18 6 6 18" />
    <path v-else-if="name === 'more'" d="M5 12h.01m6.99 0h.01m6.99 0h.01" stroke-width="2.5" />
  </svg>
</template>

<style scoped>
.app-icon {
  display: inline-block;
  flex: none;
  vertical-align: middle;
}

.app-icon__brand-detail {
  stroke: var(--accent-fg);
}
</style>
