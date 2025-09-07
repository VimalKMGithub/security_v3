package org.vimal.security.v3.encryptordecryptors;

import org.springframework.stereotype.Component;
import org.vimal.security.v3.configs.PropertiesConfig;
import org.vimal.security.v3.utils.AesRandomUtility;

import java.security.NoSuchAlgorithmException;

@Component
public class GenericAesRandomEncryptorDecryptor {
    private final AesRandomUtility aesRandomUtility;

    public GenericAesRandomEncryptorDecryptor(PropertiesConfig propertiesConfig) throws NoSuchAlgorithmException {
        this.aesRandomUtility = new AesRandomUtility(propertiesConfig.getGenericAesRandomSecretKey());
    }

    public String encrypt(String data) throws Exception {
        return aesRandomUtility.encrypt(data);
    }

    public String decrypt(String encryptedData) throws Exception {
        return aesRandomUtility.decrypt(encryptedData);
    }
}
