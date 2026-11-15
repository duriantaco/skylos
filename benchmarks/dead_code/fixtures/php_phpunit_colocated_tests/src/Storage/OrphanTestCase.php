<?php

namespace Shop\Storage;

use PHPUnit\Framework\TestCase;

abstract class OrphanTestCase extends TestCase
{
    protected function fixture(): string
    {
        return 'unused';
    }
}
