/**
 * Moderate Java Sample - Medium Complexity File & Token Controller
 * Complexity: Moderate (Cyclomatic Complexity ~ 6-9, ~65 LOC)
 * Identified OWASP Vulnerabilities:
 * 1. Path Traversal via unvalidated file access (A01:2025 / CWE-22)
 * 2. Insecure Randomness via java.util.Random for security tokens (A04:2025 / CWE-338)
 */
package com.aegis.sample;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Random;

public class ModerateSample {

    private final String baseStorageDir = "/var/app/data/uploads";

    // OWASP A04 / CWE-338: Insecure Random generator for session token
    public String generateSecurityToken() {
        Random random = new Random();
        byte[] tokenBytes = new byte[16];
        random.nextBytes(tokenBytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : tokenBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // OWASP A01 / CWE-22: Path Traversal vulnerability
    public byte[] readUploadedDocument(String userSuppliedFilename) throws IOException {
        if (userSuppliedFilename == null || userSuppliedFilename.trim().isEmpty()) {
            throw new IllegalArgumentException("Filename cannot be blank.");
        }

        // Direct path concatenation without canonical path boundary check
        File targetFile = new File(baseStorageDir, userSuppliedFilename);
        
        if (!targetFile.exists()) {
            throw new IOException("Requested document does not exist: " + userSuppliedFilename);
        }

        try (FileInputStream fis = new FileInputStream(targetFile)) {
            byte[] buffer = new byte[(int) targetFile.length()];
            fis.read(buffer);
            return buffer;
        }
    }
}
