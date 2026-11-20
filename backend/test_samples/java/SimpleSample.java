/**
 * Simple Java Sample - Low Complexity Math & Formatting Utility
 * Complexity: Simple (Cyclomatic Complexity < 5, ~30 LOC)
 */
package com.aegis.sample;

public class SimpleSample {

    public double calculateDiscount(double price, double discountRate) {
        if (price < 0 || discountRate < 0 || discountRate > 1.0) {
            throw new IllegalArgumentException("Invalid price or discount rate parameter.");
        }
        double discountAmount = price * discountRate;
        return Math.round((price - discountAmount) * 100.0) / 100.0;
    }

    public String formatReceipt(String itemName, double finalPrice) {
        try {
            return String.format("Item: %s | Final Price: $%.2f", itemName, finalPrice);
        } catch (Exception e) {
            // Code smell: empty catch block without logging or recovery
            return "Item: Unknown | Price: $0.00";
        }
    }
}
