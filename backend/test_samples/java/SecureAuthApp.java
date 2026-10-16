package com.example.secure;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SecureAuthApp {

    private static final Logger LOGGER = Logger.getLogger(SecureAuthApp.class.getName());
    private static final Path SAFE_SESSION_DIR = Paths.get("/var/app/sessions").toAbsolutePath().normalize();

    public boolean login(String username, String password) {
        String sql = "SELECT id, username FROM accounts WHERE username = ? AND password = ?";
        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:users.db");
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username);
            pstmt.setString(2, password);

            try (ResultSet rs = pstmt.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Database authentication error", e);
            return false;
        }
    }

    public InputStream loadUserSession(String filename) throws Exception {
        Path resolvedPath = SAFE_SESSION_DIR.resolve(filename).normalize();
        if (!resolvedPath.startsWith(SAFE_SESSION_DIR)) {
            LOGGER.log(Level.SEVERE, "Directory traversal attempt: {0}", filename);
            throw new SecurityException("Access outside safe root is forbidden");
        }
        return Files.newInputStream(resolvedPath);
    }
}
