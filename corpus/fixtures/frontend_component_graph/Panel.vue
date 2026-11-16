<script setup lang="ts">
import Badge from './parts/Badge.svelte';
import { summarize as label } from './helpers';

const view = label();
</script>

<template>
  <Badge :label="view" />
</template>
