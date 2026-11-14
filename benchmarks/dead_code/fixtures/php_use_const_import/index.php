<?php

require __DIR__ . '/src/Limits.php';
require __DIR__ . '/src/Cart.php';

$cart = new \App\Cart();
echo $cart->isFull(3, $cart) ? $cart->mode() : 0;
