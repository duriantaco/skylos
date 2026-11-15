<?php

namespace Shop\Storage;

use PHPUnit\Framework\TestCase;

abstract class AdapterTestCase extends TestCase
{
    abstract protected function adapter(): MemoryAdapter;

    public function testRoundTrip(): void
    {
        $adapter = $this->adapter();
        $adapter->write('a', 'b');
        self::assertSame('b', $adapter->read('a'));
    }
}
