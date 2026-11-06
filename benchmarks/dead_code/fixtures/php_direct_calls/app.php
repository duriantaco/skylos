<?php

function normalize_value(string $value): string
{
    return trim($value);
}

function format_value(string $value): string
{
    return normalize_value($value);
}

function parse_value(string $value): string
{
    return strtoupper($value);
}

echo format_value(" sample ");
