import { useScale } from './hooks/useScale';
import { Button } from './ui/Button';

export default function App() {
  return Button(useScale());
}
