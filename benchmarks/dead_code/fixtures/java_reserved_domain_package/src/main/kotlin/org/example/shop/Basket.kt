package org.example.shop

private fun count(prices: List<Int>): Int = prices.size

private fun stale(prices: List<Int>): Int = prices.sum()

fun describe(prices: List<Int>): String = "items: ${count(prices)}"
