package org.vimal.security.v3.encryptordecryptors;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.stereotype.Component;
import org.vimal.security.v3.configs.PropertiesConfig;
import org.vimal.security.v3.utils.AesRandomUtility;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Component
public class GenericAesRandomEncryptorDecryptor {
    private final AesRandomUtility aesRandomUtility;

    public GenericAesRandomEncryptorDecryptor(PropertiesConfig propertiesConfig) throws NoSuchAlgorithmException {
        this.aesRandomUtility = new AesRandomUtility(propertiesConfig.getGenericAesRandomSecretKey());
    }

    public String encrypt(String data)
            throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return aesRandomUtility.encrypt(data);
    }

    public String decrypt(String encryptedData)
            throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return aesRandomUtility.decrypt(encryptedData);
    }
}
