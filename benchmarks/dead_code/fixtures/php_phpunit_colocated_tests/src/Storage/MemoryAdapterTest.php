<?php

namespace Shop\Storage;

class MemoryAdapterTest extends AdapterTestCase
{
    protected function adapter(): MemoryAdapter
    {
        return new MemoryAdapter();
    }
}
