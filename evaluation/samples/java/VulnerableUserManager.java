package com.example.service;

import java.io.*;
import java.sql.*;
import java.security.MessageDigest;
import java.util.logging.Logger;

public class VulnerableUserManager {
    private static final Logger logger = Logger.getLogger(VulnerableUserManager.class.getName());
    private static final String DB_PASSWORD = "SuperSecretPassword123!"; // CWE-798

    public boolean authenticateUser(String username, String password) {
        try {
            // Register JDBC driver
            Class.forName("org.sqlite.JDBC");
            String dbUrl = "jdbc:sqlite:users.db";
            // Line 18: Database connection arguments
            Connection conn = DriverManager.getConnection(dbUrl, "admin", DB_PASSWORD);
            Statement stmt = conn.createStatement();
            // Line 21: SQL string concatenation
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            ResultSet rs = stmt.executeQuery(query);
            if (rs.next()) {
                return true;
            }
        } catch (Exception e) {
            logger.warning("Authentication failure: " + e.getMessage());
        }
        return false;
    }

    public void saveUserPlaintext(String username, String rawPassword) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:sqlite:users.db");
        Statement stmt = conn.createStatement();
        // CWE-256: Plaintext password storage
        String sql = "INSERT INTO users (username, password) VALUES ('" + username + "', '" + rawPassword + "')";
        stmt.executeUpdate(sql);
    }

    public byte[] hashPasswordSha1(String password) throws Exception {
        // CWE-328: Weak SHA-1 password hashing
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(password.getBytes());
    }

    public byte[] exportUserProfile(String userFolder, String filename) throws IOException {
        // CWE-22: Path traversal
        File file = new File(userFolder + "/" + filename);
        FileInputStream fis = new FileInputStream(file);
        return fis.readAllBytes();
    }

    public void logUserAction(String username, String action) {
        // CWE-117: Context-dependent log injection
        logger.info("User action processed for username: " + username + " with action: " + action);
    }

    public void printAuditSummary(String username, String role) {
        // Line 60: System.out.println string concatenation
        System.out.println("Audit summary for user: " + username + " having authorization role: " + role);
    }
}
