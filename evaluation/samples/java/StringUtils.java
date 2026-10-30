package com.infosys.springboard.util;

public final class StringUtils {
    private StringUtils() {
        // Utility class
    }

    public static boolean isBlank(String str) {
        return str == null || str.trim().isEmpty();
    }

    public static String safeTrim(String str) {
        return str != null ? str.trim() : "";
    }
}
