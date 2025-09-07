package org.vimal.security.v3.utils;

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
import org.vimal.security.v3.encryptordecryptors.GenericAesRandomEncryptorDecryptor;
import org.vimal.security.v3.encryptordecryptors.GenericAesStaticEncryptorDecryptor;
import org.vimal.security.v3.enums.MfaType;
import org.vimal.security.v3.exceptions.SimpleBadRequestException;
import org.vimal.security.v3.exceptions.UnauthorizedException;
import org.vimal.security.v3.impls.UserDetailsImpl;
import org.vimal.security.v3.models.PermissionModel;
import org.vimal.security.v3.models.RoleModel;
import org.vimal.security.v3.models.UserModel;
import org.vimal.security.v3.repos.UserRepo;
import org.vimal.security.v3.services.RedisService;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
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
    private static final AlgorithmConstraints ACCESS_TOKEN_KEY_ALGORITHM_CONSTRAINTS = new AlgorithmConstraints(
            AlgorithmConstraints.ConstraintType.PERMIT,
            KeyManagementAlgorithmIdentifiers.A256KW
    );
    private static final AlgorithmConstraints ACCESS_TOKEN_ENCRYPTION_ALGORITHM_CONSTRAINTS = new AlgorithmConstraints(
            AlgorithmConstraints.ConstraintType.PERMIT,
            ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512
    );
    private static final String ACCESS_TOKEN_ID_PREFIX = "SECURITY_V3_ACCESS_TOKEN_ID:";
    private static final String REFRESH_TOKEN_PREFIX = "SECURITY_V3_REFRESH_TOKEN:";
    private static final String REFRESH_TOKEN_MAPPING_PREFIX = "SECURITY_V3_REFRESH_TOKEN_MAPPING:";
    private final SecretKey signingKey;
    private final SecretKey encryptionKey;
    private final UserRepo userRepo;
    private final RedisService redisService;
    private final GenericAesRandomEncryptorDecryptor genericAesRandomEncryptorDecryptor;
    private final GenericAesStaticEncryptorDecryptor genericAesStaticEncryptorDecryptor;

    public AccessTokenUtility(PropertiesConfig propertiesConfig,
                              UserRepo userRepo,
                              RedisService redisService,
                              GenericAesRandomEncryptorDecryptor genericAesRandomEncryptorDecryptor,
                              GenericAesStaticEncryptorDecryptor genericAesStaticEncryptorDecryptor) throws NoSuchAlgorithmException {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64
                .decode(propertiesConfig.getAccessTokenSigningSecretKey()));
        this.encryptionKey = new SecretKeySpec(
                MessageDigest.getInstance("SHA-256")
                        .digest(propertiesConfig.getAccessTokenEncryptionSecretKey().getBytes()),
                "AES"
        );
        this.userRepo = userRepo;
        this.redisService = redisService;
        this.genericAesRandomEncryptorDecryptor = genericAesRandomEncryptorDecryptor;
        this.genericAesStaticEncryptorDecryptor = genericAesStaticEncryptorDecryptor;
    }

    private String generateAccessTokenId(UserModel user) throws Exception {
        String accessTokenId = UUID.randomUUID().toString();
        redisService.save(
                genericAesStaticEncryptorDecryptor.encrypt(ACCESS_TOKEN_ID_PREFIX + user.getId().toString()),
                genericAesRandomEncryptorDecryptor.encrypt(accessTokenId),
                ACCESS_TOKEN_EXPIRES_IN_DURATION
        );
        return accessTokenId;
    }

    private Map<String, Object> buildTokenClaims(UserModel user) throws Exception {
        Map<String, Object> claims = new HashMap<>();
        claims.put(ACCESS_TOKEN_ID.name(), generateAccessTokenId(user));
        claims.put(USER_ID.name(), user.getId().toString());
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
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A256KW);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
        jwe.setKey(encryptionKey);
        jwe.setAlgorithmConstraints(ACCESS_TOKEN_KEY_ALGORITHM_CONSTRAINTS);
        jwe.setContentEncryptionAlgorithmConstraints(ACCESS_TOKEN_ENCRYPTION_ALGORITHM_CONSTRAINTS);
        jwe.setPayload(jws);
        return jwe.getCompactSerialization();
    }

    private String generateRefreshToken(UserModel user) throws Exception {
        String encryptedRefreshTokenKey = getEncryptedRefreshTokenKey(user);
        String existingEncryptedRefreshToken = redisService.get(encryptedRefreshTokenKey);
        if (existingEncryptedRefreshToken != null) {
            return genericAesRandomEncryptorDecryptor.decrypt(existingEncryptedRefreshToken);
        }
        String refreshToken = UUID.randomUUID().toString();
        String encryptedRefreshTokenMappingKey = genericAesStaticEncryptorDecryptor.encrypt(REFRESH_TOKEN_MAPPING_PREFIX + refreshToken);
        try {
            redisService.save(
                    encryptedRefreshTokenKey,
                    genericAesRandomEncryptorDecryptor.encrypt(refreshToken),
                    REFRESH_TOKEN_EXPIRES_IN_DURATION
            );
            redisService.save(
                    encryptedRefreshTokenMappingKey,
                    genericAesRandomEncryptorDecryptor.encrypt(user.getId().toString()),
                    REFRESH_TOKEN_EXPIRES_IN_DURATION
            );
            return refreshToken;
        } catch (Exception ex) {
            redisService.deleteAll(Set.of(
                    encryptedRefreshTokenKey,
                    encryptedRefreshTokenMappingKey
            ));
            throw new RuntimeException("Failed to generate refresh token", ex);
        }
    }

    private String getEncryptedRefreshTokenKey(UserModel user) throws Exception {
        return getEncryptedRefreshTokenKey(user.getId());
    }

    private String getEncryptedRefreshTokenKey(UUID userId) throws Exception {
        return getEncryptedRefreshTokenKey(userId.toString());
    }

    private String getEncryptedRefreshTokenKey(String userId) throws Exception {
        return genericAesStaticEncryptorDecryptor.encrypt(REFRESH_TOKEN_PREFIX + userId);
    }

    private Map<String, Object> generateAccessToken(UserModel user) throws Exception {
        Map<String, Object> accessToken = new HashMap<>();
        accessToken.put("access_token", encryptToken(signToken(buildTokenClaims(user))));
        accessToken.put("expires_in_seconds", ACCESS_TOKEN_EXPIRES_IN_SECONDS);
        accessToken.put("token_type", "Bearer");
        return accessToken;
    }

    public Map<String, Object> generateTokens(UserModel user) throws Exception {
        Map<String, Object> tokens = generateAccessToken(user);
        tokens.put("refresh_token", generateRefreshToken(user));
        user.recordSuccessfulLogin();
        userRepo.save(user);
        return tokens;
    }

    private String decryptToken(String token) throws JoseException {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setKey(encryptionKey);
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
    public UserDetailsImpl verifyAccessToken(String accessToken) throws Exception {
        Claims claims = parseToken(decryptToken(accessToken));
        if (Instant.parse(claims.get(
                                ISSUED_AT.name(),
                                String.class
                        )
                )
                .isAfter(Instant.now())) {
            throw new UnauthorizedException("Invalid token");
        }
        if (Instant.parse(claims.get(
                                EXPIRATION.name(),
                                String.class
                        )
                )
                .isBefore(Instant.now())) {
            throw new UnauthorizedException("Invalid token");
        }
        String userId = claims.get(
                USER_ID.name(),
                String.class
        );
        String encryptedAccessTokenId = redisService.get(genericAesStaticEncryptorDecryptor.encrypt(ACCESS_TOKEN_ID_PREFIX + userId));
        if (encryptedAccessTokenId == null) {
            throw new UnauthorizedException("Invalid token");
        }
        if (!genericAesRandomEncryptorDecryptor.decrypt(encryptedAccessTokenId)
                .equals(claims.get(
                                ACCESS_TOKEN_ID.name(),
                                String.class
                        )
                )
        ) {
            throw new UnauthorizedException("Invalid token");
        }
        UserModel user = new UserModel();
        user.setId(UUID.fromString(userId));
        user.setUsername(claims.get(
                USERNAME.name(),
                String.class
        ));
        user.setEmail(claims.get(
                EMAIL.name(),
                String.class
        ));
        user.setRealEmail(claims.get(
                REAL_EMAIL.name(),
                String.class
        ));
        user.setMfaEnabled(claims.get(
                MFA_ENABLED.name(),
                Boolean.class
        ));
        Set<MfaType> mfaMethods = new HashSet<>();
        for (String mfaMethod : (List<String>) claims.get(
                MFA_METHODS.name(),
                List.class
        )) {
            mfaMethods.add(MfaType.valueOf(mfaMethod));
        }
        user.setMfaMethods(mfaMethods);
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        for (String authority : (List<String>) claims.get(
                AUTHORITIES.name(),
                List.class
        )) {
            authorities.add(new SimpleGrantedAuthority(authority));
        }
        return new UserDetailsImpl(user, authorities);
    }

    private String getEncryptedAccessTokenIdKey(UserModel user) throws Exception {
        return getEncryptedAccessTokenIdKey(user.getId());
    }

    private String getEncryptedAccessTokenIdKey(UUID userId) throws Exception {
        return getEncryptedAccessTokenIdKey(userId.toString());
    }

    private String getEncryptedAccessTokenIdKey(String userId) throws Exception {
        return genericAesStaticEncryptorDecryptor.encrypt(ACCESS_TOKEN_ID_PREFIX + userId);
    }

    public void revokeAccessToken(UserModel user) throws Exception {
        redisService.delete(getEncryptedAccessTokenIdKey(user));
    }

    private String getEncryptedRefreshTokenMappingKey(String encryptedRefreshToken) throws Exception {
        return genericAesStaticEncryptorDecryptor.encrypt(REFRESH_TOKEN_MAPPING_PREFIX + genericAesRandomEncryptorDecryptor.decrypt(encryptedRefreshToken));
    }

    public void revokeTokens(Set<UserModel> users) throws Exception {
        Set<String> encryptedKeys = new HashSet<>();
        Set<String> encryptedRefreshTokenKeys = new HashSet<>();
        String tempStr;
        for (UserModel user : users) {
            encryptedKeys.add(getEncryptedAccessTokenIdKey(user));
            tempStr = getEncryptedRefreshTokenKey(user);
            encryptedKeys.add(tempStr);
            encryptedRefreshTokenKeys.add(tempStr);
        }
        proceedAndRevokeTokens(
                encryptedKeys,
                encryptedRefreshTokenKeys
        );
    }

    private void proceedAndRevokeTokens(Set<String> encryptedKeys,
                                        Set<String> encryptedRefreshTokenKeys) throws Exception {
        for (String encryptedRefreshToken : redisService.getAll(encryptedRefreshTokenKeys)) {
            if (encryptedRefreshToken != null) {
                encryptedKeys.add(getEncryptedRefreshTokenMappingKey(encryptedRefreshToken));
            }
        }
        if (!encryptedKeys.isEmpty()) {
            redisService.deleteAll(encryptedKeys);
        }
    }

    public void revokeTokensByUsersIds(Set<UUID> userIds) throws Exception {
        Set<String> encryptedKeys = new HashSet<>();
        Set<String> encryptedRefreshTokenKeys = new HashSet<>();
        String tempStr;
        for (UUID userId : userIds) {
            encryptedKeys.add(getEncryptedAccessTokenIdKey(userId));
            tempStr = getEncryptedRefreshTokenKey(userId);
            encryptedKeys.add(tempStr);
            encryptedRefreshTokenKeys.add(tempStr);
        }
        proceedAndRevokeTokens(
                encryptedKeys,
                encryptedRefreshTokenKeys
        );
    }

    public void revokeRefreshToken(String refreshToken) throws Exception {
        String encryptedRefreshTokenMappingKey = getEncryptedRefreshTokenMappingKeyUnencryptedRefreshToken(refreshToken);
        redisService.deleteAll(Set.of(
                        encryptedRefreshTokenMappingKey,
                        genericAesStaticEncryptorDecryptor.encrypt(REFRESH_TOKEN_PREFIX + getUserId(encryptedRefreshTokenMappingKey))
                )
        );
    }

    private String getEncryptedRefreshTokenMappingKeyUnencryptedRefreshToken(String refreshToken) throws Exception {
        return genericAesStaticEncryptorDecryptor.encrypt(REFRESH_TOKEN_MAPPING_PREFIX + refreshToken);
    }

    private String getUserId(String encryptedRefreshTokenMappingKey) throws Exception {
        String encryptedUserId = redisService.get(encryptedRefreshTokenMappingKey);
        if (encryptedUserId != null) {
            return genericAesRandomEncryptorDecryptor.decrypt(encryptedUserId);
        }
        throw new SimpleBadRequestException("Invalid refresh token");
    }

    private UserModel verifyRefreshToken(String refreshToken) throws Exception {
        String userId = getUserId(getEncryptedRefreshTokenMappingKeyUnencryptedRefreshToken(refreshToken));
        String encryptedRefreshToken = redisService.get(genericAesStaticEncryptorDecryptor.encrypt(REFRESH_TOKEN_PREFIX + userId));
        if (encryptedRefreshToken != null) {
            return userRepo.findById(UUID.fromString(userId)).orElseThrow(() -> new SimpleBadRequestException("Invalid refresh token"));
        }
        throw new SimpleBadRequestException("Invalid refresh token");
    }

    public Map<String, Object> refreshAccessToken(String refreshToken) throws Exception {
        return generateAccessToken(verifyRefreshToken(refreshToken));
    }
}
