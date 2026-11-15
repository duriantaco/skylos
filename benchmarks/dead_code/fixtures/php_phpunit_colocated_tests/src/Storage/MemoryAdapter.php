<?php

namespace Shop\Storage;

class MemoryAdapter
{
    private array $data = [];

    public function write(string $key, string $value): void
    {
        $this->data[$key] = $value;
    }

    public function read(string $key): ?string
    {
        return $this->data[$key] ?? null;
    }
}
