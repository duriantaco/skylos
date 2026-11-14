package com.example.shop;

import java.util.List;

public class Cart {
    public int total(List<Integer> prices) {
        return sum(prices);
    }

    private int sum(List<Integer> prices) {
        int total = 0;
        for (int price : prices) {
            total += price;
        }
        return total;
    }

    private int stale(List<Integer> prices) {
        return prices.size();
    }
}
