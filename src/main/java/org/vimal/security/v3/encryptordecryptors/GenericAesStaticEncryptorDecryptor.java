package org.vimal.security.v3.encryptordecryptors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;
import org.vimal.security.v3.configs.PropertiesConfig;
import org.vimal.security.v3.utils.AesStaticUtility;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Component
public class GenericAesStaticEncryptorDecryptor {
    private final AesStaticUtility aesStaticUtility;

    public GenericAesStaticEncryptorDecryptor(PropertiesConfig propertiesConfig, ObjectMapper objectMapper) throws NoSuchAlgorithmException {
        this.aesStaticUtility = new AesStaticUtility(propertiesConfig.getGenericAesStaticSecretKey(), objectMapper);
    }

    public String encrypt(Object data) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return aesStaticUtility.encrypt(data);
    }

    public <T> T decrypt(String encryptedData, Class<T> targetClass) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return aesStaticUtility.decrypt(encryptedData, targetClass);
    }
}
