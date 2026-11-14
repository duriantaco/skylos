import { noop, spare } from './util';

const DEFAULT_MIN = 100;
const DEFAULT_MAX = 500;

export function open(options: { onClose?: () => void } = {}) {
  const { onClose = noop } = options;
  onClose();
}

export const size = ({ min = DEFAULT_MIN }: { min?: number }) => min;
