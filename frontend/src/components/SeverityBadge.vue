<script setup>
import { severityLabels } from '../format'
defineProps({ severity: { type: String, default: 'UNKNOWN' } })
</script>

<template>
  <span class="severity-badge" :class="severity.toLowerCase()">
    <span class="badge-dot"></span>
    {{ severityLabels[severity] || severity }}
  </span>
</template>
