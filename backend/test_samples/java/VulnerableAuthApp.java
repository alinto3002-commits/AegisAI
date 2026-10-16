package com.example.vulnerable;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class VulnerableAuthApp {

    // Hardcoded Secret (OWASP A07:2025)
    private static final String API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";

    public boolean login(String username, String password) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:sqlite:users.db");
            Statement stmt = conn.createStatement();

            // SQL Injection via string concatenation (OWASP A05:2025)
            String sql = "SELECT * FROM accounts WHERE username = '" + username + "' AND password = '" + password + "'";
            ResultSet rs = stmt.executeQuery(sql);

            return rs.next();
        } catch (Exception e) {
            // Empty catch block (OWASP A10:2025)
        }
        return false;
    }

    public Object loadUserSession(String filename) {
        try {
            // Path Traversal (OWASP A01:2025)
            File file = new File("/var/app/sessions/" + filename);
            FileInputStream fis = new FileInputStream(file);

            // Insecure Deserialization via ObjectInputStream (OWASP A08:2025)
            ObjectInputStream ois = new ObjectInputStream(fis);
            return ois.readObject();
        } catch (Exception e) {
            return null;
        }
    }
}
