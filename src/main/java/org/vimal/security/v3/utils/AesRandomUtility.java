package org.vimal.security.v3.utils;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class AesRandomUtility {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final SecureRandom secureRandom = new SecureRandom();
    private final SecretKey secretKey;

    public AesRandomUtility(String aesSecret) throws NoSuchAlgorithmException {
        this.secretKey = new SecretKeySpec(
                MessageDigest.getInstance("SHA-256")
                        .digest(aesSecret.getBytes()),
                "AES"
        );
    }

    public String encrypt(String data)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
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

    public String decrypt(String encryptedData)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
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
