package com.infosys.springboard.service;

import java.util.List;

public class OrderProcessor {
    public void processBatch(List<String> orders) {
        try {
            for (String order : orders) {
                if (order != null) {
                    if (order.startsWith("ORD-")) {
                        if (order.length() > 5) {
                            if (!order.contains("CANCELLED")) {
                                System.out.println("Processing valid order: " + order);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Empty catch block silently swallowing exceptions (CWE-390)
        }
    }
}
