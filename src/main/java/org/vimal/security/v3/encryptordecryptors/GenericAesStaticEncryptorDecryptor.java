package org.vimal.security.v3.encryptordecryptors;

import org.springframework.stereotype.Component;
import org.vimal.security.v3.configs.PropertiesConfig;
import org.vimal.security.v3.utils.AesStaticUtility;

import java.security.NoSuchAlgorithmException;

@Component
public class GenericAesStaticEncryptorDecryptor {
    private final AesStaticUtility aesStaticUtility;

    public GenericAesStaticEncryptorDecryptor(PropertiesConfig propertiesConfig) throws NoSuchAlgorithmException {
        this.aesStaticUtility = new AesStaticUtility(propertiesConfig.getGenericAesStaticSecretKey());
    }

    public String encrypt(String data) throws Exception {
        return aesStaticUtility.encrypt(data);
    }

    public String decrypt(String encryptedData) throws Exception {
        return aesStaticUtility.decrypt(encryptedData);
    }
}
