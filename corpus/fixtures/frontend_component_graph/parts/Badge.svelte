<script lang="ts">
import Tile from './Tile.astro';
import { format } from './helpers';

const text = format();
</script>

<Tile label={text} />
