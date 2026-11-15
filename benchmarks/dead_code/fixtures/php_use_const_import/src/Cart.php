<?php

namespace App;

use const App\Config\COMMENT_ONLY;
use const App\Config\DEFAULT_MODE;
use const App\Config\MAX_ITEMS;
use const App\Config\MEMBER_ONLY;
use const App\Config\UNUSED_LIMIT;

final class Cart
{
    public const MEMBER_ONLY = 2;

    public function __construct(private int $mode = DEFAULT_MODE)
    {
    }

    public function isFull(int $count, Cart $other): bool
    {
        return $count >= MAX_ITEMS || $other::MEMBER_ONLY === self::MEMBER_ONLY;
    }

    public function mode(): int
    {
        // COMMENT_ONLY used to cap the mode here.
        return $this->mode;
    }
}
