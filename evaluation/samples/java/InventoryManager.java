package com.infosys.springboard.repository;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class InventoryManager {
    public int getStockLevel(String sku) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/shop", "user", "pass");
        Statement stmt = conn.createStatement();
        // SQL Injection via string concatenation (CWE-89)
        ResultSet rs = stmt.executeQuery("SELECT quantity FROM items WHERE sku = '" + sku + "'");
        if (rs.next()) {
            return rs.getInt("quantity");
        }
        return 0;
    }
}
