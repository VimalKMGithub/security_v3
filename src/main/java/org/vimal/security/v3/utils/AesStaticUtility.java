package org.vimal.security.v3.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AesStaticUtility {
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final byte[] FIXED_IV = new byte[16];
    private static final IvParameterSpec FIXED_IV_SPEC = new IvParameterSpec(FIXED_IV);
    private final ObjectMapper objectMapper;
    private final SecretKey secretKey;

    public AesStaticUtility(String aesSecret,
                            ObjectMapper objectMapper) throws NoSuchAlgorithmException {
        this.secretKey = new SecretKeySpec(MessageDigest.getInstance("SHA-256")
                .digest(aesSecret.getBytes()),
                "AES");
        this.objectMapper = objectMapper;
    }

    public String encrypt(Object data)
            throws JsonProcessingException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return encryptString(objectMapper.writeValueAsString(data));
    }

    private String encryptString(String data)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(
                Cipher.ENCRYPT_MODE,
                secretKey,
                FIXED_IV_SPEC
        );
        return Base64.getEncoder()
                .encodeToString(cipher.doFinal(data.getBytes()));
    }

    public <T> T decrypt(String encryptedData,
                         Class<T> targetClass)
            throws JsonProcessingException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return objectMapper.readValue(
                decryptString(encryptedData),
                targetClass
        );
    }

    private String decryptString(String encryptedData)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
                FIXED_IV_SPEC
        );
        return new String(cipher.doFinal(Base64.getDecoder()
                .decode(encryptedData)));
    }
}
