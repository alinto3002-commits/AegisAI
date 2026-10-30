package com.infosys.springboard.service;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class CommandRunner {
    public String executeUserDiagnostic(String commandArg) throws Exception {
        // OS Command Injection vulnerability (CWE-78)
        Process process = Runtime.getRuntime().exec("sh -c " + commandArg);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }
}
