package com.infosys.springboard.service;

import java.util.Random;
import java.util.Base64;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AuthService {
    private static final String JWT_SECRET = "my-jwt-secret-2024";
    private static final byte[] AES_KEY = "0123456789abcdef".getBytes();

    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return Base64.getEncoder().encodeToString(md.digest(password.getBytes()));
    }

    public String createResetToken() {
        Random random = new Random();
        return Long.toHexString(random.nextLong());
    }

    public byte[] encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(AES_KEY, "AES"));
        return cipher.doFinal(data.getBytes());
    }
}
