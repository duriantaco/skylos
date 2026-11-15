import type * as sdk from 'remote-sdk';
import type * as spareNs from 'remote-sdk';
import type { Gone } from 'remote-sdk';
import type { Kept } from 'remote-sdk';

export function run(state: sdk.multi.Progress, kept: Kept): number {
  return state.n + kept.n;
}
