package com.infosys.springboard.repository;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class UserRepository {
    private static final String DB_PASSWORD = "production-db-root-pwd-99";

    public boolean authenticateUser(String username, String password) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/users", "postgres", DB_PASSWORD);
        Statement stmt = conn.createStatement();
        // SQL Injection concatenation vulnerability (CWE-89)
        String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        ResultSet rs = stmt.executeQuery(sql);
        return rs.next();
    }
}
