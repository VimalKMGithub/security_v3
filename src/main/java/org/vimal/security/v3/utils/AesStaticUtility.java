package org.vimal.security.v3.utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AesStaticUtility {
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final byte[] FIXED_IV = new byte[16];
    private static final IvParameterSpec FIXED_IV_SPEC = new IvParameterSpec(FIXED_IV);
    private final SecretKey secretKey;

    public AesStaticUtility(String aesSecret) throws NoSuchAlgorithmException {
        this.secretKey = new SecretKeySpec(
                MessageDigest.getInstance("SHA-256")
                        .digest(aesSecret.getBytes()),
                "AES"
        );
    }

    public String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(
                Cipher.ENCRYPT_MODE,
                secretKey,
                FIXED_IV_SPEC
        );
        return Base64.getEncoder()
                .encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    public String decrypt(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
                FIXED_IV_SPEC
        );
        return new String(
                cipher.doFinal(Base64.getDecoder()
                        .decode(encryptedData)),
                StandardCharsets.UTF_8
        );
    }
}
