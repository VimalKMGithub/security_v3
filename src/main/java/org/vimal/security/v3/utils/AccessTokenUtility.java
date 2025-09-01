package org.vimal.security.v3.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;
import org.vimal.security.v3.configs.PropertiesConfig;
import org.vimal.security.v3.converter.GenericAesRandomConverter;
import org.vimal.security.v3.converter.GenericAesStaticConverter;
import org.vimal.security.v3.models.UserModel;
import org.vimal.security.v3.repos.UserRepo;
import org.vimal.security.v3.services.RedisService;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Component
public class AccessTokenUtility {
    private static final long ACCESS_TOKEN_EXPIRES_IN_SECONDS = TimeUnit.MINUTES.toSeconds(30);
    private static final long REFRESH_TOKEN_EXPIRES_IN_SECONDS = TimeUnit.MINUTES.toSeconds(60 * 24 * 7);
    private static final Duration ACCESS_TOKEN_EXPIRES_IN_DURATION = Duration.ofSeconds(ACCESS_TOKEN_EXPIRES_IN_SECONDS);
    private static final Duration REFRESH_TOKEN_EXPIRES_IN_DURATION = Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_IN_SECONDS);
    private static final String ACCESS_TOKEN_ID_PREFIX = "SECURITY_V2_ACCESS_TOKEN_ID:";
    private static final String REFRESH_TOKEN_PREFIX = "SECURITY_V2_REFRESH_TOKEN:";
    private static final String REFRESH_TOKEN_MAPPING_PREFIX = "SECURITY_V2_REFRESH_TOKEN_MAPPING:";
    private final SecretKey signingKey;
    private final SecretKey encryptionKey;
    private final UserRepo userRepo;
    private final RedisService redisService;
    private final GenericAesRandomConverter genericAesRandomConverter;
    private final GenericAesStaticConverter genericAesStaticConverter;

    public AccessTokenUtility(PropertiesConfig propertiesConfig, UserRepo userRepo, RedisService redisService, GenericAesRandomConverter genericAesRandomConverter, GenericAesStaticConverter genericAesStaticConverter) throws NoSuchAlgorithmException {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(propertiesConfig.getAccessTokenSigningSecretKey()));
        this.encryptionKey = new SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(propertiesConfig.getAccessTokenEncryptionSecretKey().getBytes()), "AES");
        this.userRepo = userRepo;
        this.redisService = redisService;
        this.genericAesRandomConverter = genericAesRandomConverter;
        this.genericAesStaticConverter = genericAesStaticConverter;
    }

    private UUID generateAccessTokenId(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UUID accessTokenId = UUID.randomUUID();
        redisService.save(genericAesStaticConverter.encrypt(ACCESS_TOKEN_ID_PREFIX + user.getId()), genericAesRandomConverter.encrypt(accessTokenId));
        return accessTokenId;
    }
}
