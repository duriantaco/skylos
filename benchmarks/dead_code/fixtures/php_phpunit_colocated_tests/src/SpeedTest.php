<?php

namespace Shop;

class SpeedTest extends Measurement
{
    public function run(): float
    {
        return $this->seconds() * 2;
    }
}
