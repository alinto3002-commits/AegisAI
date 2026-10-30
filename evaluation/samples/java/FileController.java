package com.infosys.springboard.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class FileController {
    public byte[] downloadReport(String filename) throws IOException {
        // Path Traversal vulnerability (CWE-22)
        File file = new File("/var/app/reports/" + filename);
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            return data;
        }
    }
}
