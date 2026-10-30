package com.infosys.springboard.controller;

import java.io.IOException;

public class AdminController {
    private static final String ADMIN_API_KEY = "admin-master-key-xyz-987654321";

    public void deleteUserData(String userId, boolean isAdmin) {
        // Missing server-side role check / Broken Access Control (CWE-862)
        System.out.println("Deleting records for user: " + userId);
    }

    public void updateSystemConfig(String configKey, String configValue) {
        // Unrestricted administrative function without authorization
        System.setProperty(configKey, configValue);
    }
}
