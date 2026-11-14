import { useTimeout, useEnsured } from '../src';

test('x', () => {
  useTimeout(1);
  useEnsured({ current: 1 });
});
