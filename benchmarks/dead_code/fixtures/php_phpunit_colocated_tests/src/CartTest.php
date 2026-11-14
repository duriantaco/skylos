<?php

namespace Shop;

use PHPUnit\Framework\TestCase;

final class CartTest extends TestCase
{
    public function testAddCountsItems(): void
    {
        $cart = new Cart();
        self::assertSame(1, $cart->add('pen'));
    }
}
