<script lang="ts">
  import type { BadgeProps } from "../shapes";

  let { label }: BadgeProps = $props();
</script>

<span>{label}</span>
