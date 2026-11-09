<?php

class Formatter
{
    public function format(string $value): string
    {
        return $this->normalize($value);
    }

    private function normalize(string $value): string
    {
        return trim($value);
    }

    private function summarize(string $value): string
    {
        return strtoupper($value);
    }
}

$formatter = new Formatter();
echo $formatter->format(" sample ");
