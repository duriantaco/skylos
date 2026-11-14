<?php

namespace Shop;

class Cart
{
    private array $items = [];

    public function add(string $item): int
    {
        $this->items[] = $item;

        return count($this->items);
    }
}
