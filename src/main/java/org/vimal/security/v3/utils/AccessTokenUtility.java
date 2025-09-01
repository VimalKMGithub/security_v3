package org.vimal.security.v3.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.lang.JoseException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.vimal.security.v3.configs.PropertiesConfig;
import org.vimal.security.v3.converter.GenericAesRandomConverter;
import org.vimal.security.v3.converter.GenericAesStaticConverter;
import org.vimal.security.v3.enums.MfaType;
import org.vimal.security.v3.exceptions.SimpleBadRequestException;
import org.vimal.security.v3.exceptions.UnauthorizedException;
import org.vimal.security.v3.impls.UserDetailsImpl;
import org.vimal.security.v3.models.PermissionModel;
import org.vimal.security.v3.models.RoleModel;
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
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.vimal.security.v3.enums.AccessTokenClaims.*;

@Component
public class AccessTokenUtility {
    private static final long ACCESS_TOKEN_EXPIRES_IN_SECONDS = TimeUnit.MINUTES.toSeconds(30);
    private static final long REFRESH_TOKEN_EXPIRES_IN_SECONDS = TimeUnit.MINUTES.toSeconds(60 * 24 * 7);
    private static final Duration ACCESS_TOKEN_EXPIRES_IN_DURATION = Duration.ofSeconds(ACCESS_TOKEN_EXPIRES_IN_SECONDS);
    private static final Duration REFRESH_TOKEN_EXPIRES_IN_DURATION = Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_IN_SECONDS);
    private static final AlgorithmConstraints ACCESS_TOKEN_KEY_ALGORITHM_CONSTRAINTS = new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, KeyManagementAlgorithmIdentifiers.A256KW);
    private static final AlgorithmConstraints ACCESS_TOKEN_ENCRYPTION_ALGORITHM_CONSTRAINTS = new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
    private static final String ACCESS_TOKEN_ID_PREFIX = "SECURITY_V2_ACCESS_TOKEN_ID:";
    private static final String REFRESH_TOKEN_PREFIX = "SECURITY_V2_REFRESH_TOKEN:";
    private static final String REFRESH_TOKEN_MAPPING_PREFIX = "SECURITY_V2_REFRESH_TOKEN_MAPPING:";
    private final SecretKey signingKey;
    private final SecretKey encryptionKey;
    private final UserRepo userRepo;
    private final RedisService redisService;
    private final GenericAesRandomConverter genericAesRandomConverter;
    private final GenericAesStaticConverter genericAesStaticConverter;
    private final ThreadLocal<JsonWebEncryption> jweEncryptor;
    private final ThreadLocal<JsonWebEncryption> jweDecryptor;

    public AccessTokenUtility(PropertiesConfig propertiesConfig, UserRepo userRepo, RedisService redisService, GenericAesRandomConverter genericAesRandomConverter, GenericAesStaticConverter genericAesStaticConverter) throws NoSuchAlgorithmException {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(propertiesConfig.getAccessTokenSigningSecretKey()));
        this.encryptionKey = new SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(propertiesConfig.getAccessTokenEncryptionSecretKey().getBytes()), "AES");
        this.userRepo = userRepo;
        this.redisService = redisService;
        this.genericAesRandomConverter = genericAesRandomConverter;
        this.genericAesStaticConverter = genericAesStaticConverter;
        this.jweEncryptor = ThreadLocal.withInitial(() -> {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A256KW);
            jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
            jwe.setKey(encryptionKey);
            jwe.setAlgorithmConstraints(ACCESS_TOKEN_KEY_ALGORITHM_CONSTRAINTS);
            jwe.setContentEncryptionAlgorithmConstraints(ACCESS_TOKEN_ENCRYPTION_ALGORITHM_CONSTRAINTS);
            return jwe;
        });
        this.jweDecryptor = ThreadLocal.withInitial(() -> {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setKey(encryptionKey);
            return jwe;
        });
    }

    private UUID generateAccessTokenId(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UUID accessTokenId = UUID.randomUUID();
        redisService.save(genericAesStaticConverter.encrypt(ACCESS_TOKEN_ID_PREFIX + user.getId()), genericAesRandomConverter.encrypt(accessTokenId));
        return accessTokenId;
    }

    private Map<String, Object> buildTokenClaims(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        Map<String, Object> claims = new HashMap<>();
        claims.put(ACCESS_TOKEN_ID.name(), generateAccessTokenId(user));
        claims.put(USER_ID.name(), user.getId());
        claims.put(USERNAME.name(), user.getUsername());
        claims.put(EMAIL.name(), user.getEmail());
        claims.put(REAL_EMAIL.name(), user.getRealEmail());
        Set<String> authorities = new HashSet<>();
        for (RoleModel role : user.getRoles()) {
            authorities.add(role.getRoleName());
            for (PermissionModel permission : role.getPermissions()) {
                authorities.add(permission.getPermissionName());
            }
        }
        claims.put(AUTHORITIES.name(), authorities);
        claims.put(MFA_ENABLED.name(), user.isMfaEnabled());
        Set<String> mfaMethods = new HashSet<>();
        for (MfaType mfaType : user.getMfaMethods()) {
            mfaMethods.add(mfaType.name());
        }
        claims.put(MFA_METHODS.name(), mfaMethods);
        Instant now = Instant.now();
        claims.put(ISSUED_AT.name(), now.toString());
        claims.put(EXPIRATION.name(), now.plusSeconds(ACCESS_TOKEN_EXPIRES_IN_SECONDS).toString());
        return claims;
    }

    private String signToken(Map<String, Object> claims) {
        return Jwts.builder()
                .claims(claims)
                .signWith(signingKey)
                .compact();
    }

    private String encryptToken(String jws) throws JoseException {
        JsonWebEncryption jwe = jweEncryptor.get();
        jwe.setPayload(jws);
        return jwe.getCompactSerialization();
    }

    private UUID generateRefreshToken(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        String encryptedRefreshTokenKey = getEncryptedRefreshTokenKey(user);
        Object existingEncryptedRefreshToken = redisService.get(encryptedRefreshTokenKey);
        if (existingEncryptedRefreshToken != null) {
            return genericAesRandomConverter.decrypt((String) existingEncryptedRefreshToken, UUID.class);
        }
        UUID refreshToken = UUID.randomUUID();
        String encryptedRefreshTokenMappingKey = genericAesStaticConverter.encrypt(REFRESH_TOKEN_MAPPING_PREFIX + refreshToken);
        try {
            redisService.save(encryptedRefreshTokenKey, genericAesRandomConverter.encrypt(refreshToken), REFRESH_TOKEN_EXPIRES_IN_DURATION);
            redisService.save(encryptedRefreshTokenMappingKey, genericAesRandomConverter.encrypt(user.getId()), REFRESH_TOKEN_EXPIRES_IN_DURATION);
            return refreshToken;
        } catch (Exception ex) {
            redisService.deleteAll(Set.of(encryptedRefreshTokenKey, encryptedRefreshTokenMappingKey));
            throw new RuntimeException("Failed to generate refresh token", ex);
        }
    }

    private String getEncryptedRefreshTokenKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return getEncryptedRefreshTokenKey(user.getId());
    }

    private String getEncryptedRefreshTokenKey(UUID userId) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return genericAesStaticConverter.encrypt(REFRESH_TOKEN_PREFIX + userId);
    }

    private Map<String, Object> generateAccessToken(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException, JoseException {
        Map<String, Object> accessToken = new HashMap<>();
        accessToken.put("access_token", encryptToken(signToken(buildTokenClaims(user))));
        accessToken.put("expires_in_seconds", ACCESS_TOKEN_EXPIRES_IN_SECONDS);
        accessToken.put("token_type", "Bearer");
        return accessToken;
    }

    public Map<String, Object> generateTokens(UserModel user) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        Map<String, Object> tokens = generateAccessToken(user);
        tokens.put("refresh_token", generateRefreshToken(user));
        user.recordSuccessfulLogin();
        userRepo.save(user);
        return tokens;
    }

    private String decryptToken(String token) throws JoseException {
        JsonWebEncryption jwe = jweDecryptor.get();
        jwe.setCompactSerialization(token);
        return jwe.getPayload();
    }

    private Claims parseToken(String jws) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(jws)
                .getPayload();
    }

    @SuppressWarnings("unchecked")
    public UserDetailsImpl verifyAccessToken(String accessToken) throws JoseException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        Claims claims = parseToken(decryptToken(accessToken));
        if (Instant.parse(claims.get(ISSUED_AT.name(), String.class)).isAfter(Instant.now())) {
            throw new UnauthorizedException("Invalid token");
        }
        if (Instant.parse(claims.get(EXPIRATION.name(), String.class)).isBefore(Instant.now())) {
            throw new UnauthorizedException("Invalid token");
        }
        String userId = claims.get(USER_ID.name(), String.class);
        Object encryptedAccessTokenId = redisService.get(genericAesStaticConverter.encrypt(ACCESS_TOKEN_ID_PREFIX + userId));
        if (encryptedAccessTokenId == null) {
            throw new UnauthorizedException("Invalid token");
        }
        if (!genericAesRandomConverter.decrypt((String) encryptedAccessTokenId, String.class).equals(claims.get(ACCESS_TOKEN_ID.name(), String.class))) {
            throw new UnauthorizedException("Invalid token");
        }
        UserModel user = new UserModel();
        user.setId(UUID.fromString(userId));
        user.setUsername(claims.get(USERNAME.name(), String.class));
        user.setEmail(claims.get(EMAIL.name(), String.class));
        user.setRealEmail(claims.get(REAL_EMAIL.name(), String.class));
        user.setMfaEnabled(claims.get(MFA_ENABLED.name(), Boolean.class));
        Set<MfaType> mfaMethods = new HashSet<>();
        for (var mfaMethod : (List<String>) claims.get(MFA_METHODS.name(), List.class)) {
            mfaMethods.add(MfaType.valueOf(mfaMethod));
        }
        user.setMfaMethods(mfaMethods);
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        for (var authority : (List<String>) claims.get(AUTHORITIES.name(), List.class)) {
            authorities.add(new SimpleGrantedAuthority(authority));
        }
        return new UserDetailsImpl(user, authorities);
    }
}
