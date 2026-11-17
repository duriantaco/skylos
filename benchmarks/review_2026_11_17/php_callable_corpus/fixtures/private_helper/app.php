<?php
namespace Review;

use RuntimeException;
use function htmlentities;

class Resolver {
    public function run($value) {
        return $this->dispatch($value, [$this, 'isRoute'])
            || $this->dispatch($value, [$this, 'isMiddleware']);
    }

    private function dispatch($value, callable $predicate) {
        return $predicate($value);
    }

    private function isRoute($value) { return is_array($value); }
    private function isMiddleware($value) { return is_object($value); }

    private function dormant() {
        return $this->dispatch(null, [$this, 'deadCallback']);
    }

    private function deadCallback($value) { return false; }
    private function unusedSibling() { return false; }
}

class Other {
    private function isRoute() { return false; }
}

(new Resolver())->run([]);
new Other();
