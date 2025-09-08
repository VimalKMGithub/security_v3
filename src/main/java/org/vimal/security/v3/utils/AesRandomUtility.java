package org.vimal.security.v3.utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AesRandomUtility {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final ThreadLocal<SecureRandom> SECURE_RANDOM = ThreadLocal.withInitial(SecureRandom::new);
    private final SecretKey secretKey;

    public AesRandomUtility(String aesSecret) throws NoSuchAlgorithmException {
        this.secretKey = new SecretKeySpec(
                MessageDigest.getInstance("SHA-256")
                        .digest(aesSecret.getBytes()),
                "AES"
        );
    }

    public String encrypt(String data) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SECURE_RANDOM.get()
                .nextBytes(iv);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(
                Cipher.ENCRYPT_MODE,
                secretKey,
                new GCMParameterSpec(
                        GCM_TAG_LENGTH,
                        iv
                )
        );
        return Base64.getEncoder()
                .encodeToString(iv) + ":" + Base64.getEncoder()
                .encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    public String decrypt(String encryptedData) throws Exception {
        String[] parts = encryptedData.split(":");
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
                new GCMParameterSpec(
                        GCM_TAG_LENGTH,
                        Base64.getDecoder()
                                .decode(parts[0])
                )
        );
        return new String(
                cipher.doFinal(Base64.getDecoder()
                        .decode(parts[1])),
                StandardCharsets.UTF_8
        );
    }
}
