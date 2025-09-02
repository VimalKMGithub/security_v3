package org.vimal.security.v3.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.jose4j.lang.JoseException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.vimal.security.v3.encryptordecryptors.GenericAesRandomEncryptorDecryptor;
import org.vimal.security.v3.encryptordecryptors.GenericAesStaticEncryptorDecryptor;
import org.vimal.security.v3.exceptions.SimpleBadRequestException;
import org.vimal.security.v3.models.UserModel;
import org.vimal.security.v3.repos.UserRepo;
import org.vimal.security.v3.utils.AccessTokenUtility;
import org.vimal.security.v3.utils.UnleashUtility;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.vimal.security.v3.enums.FeatureFlags.FORCE_MFA;
import static org.vimal.security.v3.enums.FeatureFlags.MFA;
import static org.vimal.security.v3.enums.MfaType.EMAIL_MFA;
import static org.vimal.security.v3.utils.UserUtility.getCurrentAuthenticatedUser;
import static org.vimal.security.v3.utils.ValidationUtility.*;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private static final Set<String> TOGGLE_TYPE = Set.of("enable", "disable");
    private static final String STATE_TOKEN_PREFIX = "SECURITY_V2_STATE_TOKEN:";
    private static final String STATE_TOKEN_MAPPING_PREFIX = "SECURITY_V2_STATE_TOKEN_MAPPING:";
    private static final String EMAIL_MFA_OTP_PREFIX = "SECURITY_V2_EMAIL_MFA_OTP:";
    private static final String AUTHENTICATOR_APP_SECRET_PREFIX = "SECURITY_V2_AUTHENTICATOR_APP_SECRET:";
    private final AuthenticationManager authenticationManager;
    private final AccessTokenUtility accessTokenUtility;
    private final RedisService redisService;
    private final UserRepo userRepo;
    private final MailService mailService;
    private final Unleash unleash;
    private final UnleashUtility unleashUtility;
    private final GenericAesStaticEncryptorDecryptor genericAesStaticEncryptorDecryptor;
    private final GenericAesRandomEncryptorDecryptor genericAesRandomEncryptorDecryptor;

    public Map<String, Object> login(String usernameOrEmail, String password) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            validateStringIsNonNullAndNotBlank(usernameOrEmail, "Username/email");
            validatePassword(password);
        } catch (SimpleBadRequestException ex) {
            throw new BadCredentialsException("Invalid credentials");
        }
        UserModel user;
        if (EMAIL_PATTERN.matcher(usernameOrEmail).matches()) {
            user = userRepo.findByEmail(usernameOrEmail);
            if (user == null) {
                throw new BadCredentialsException("Invalid credentials");
            }
        } else if (USERNAME_PATTERN.matcher(usernameOrEmail).matches()) {
            user = userRepo.findByUsername(usernameOrEmail);
            if (user == null) {
                throw new BadCredentialsException("Invalid credentials");
            }
        } else {
            throw new BadCredentialsException("Invalid credentials");
        }
        return proceedLogin(user, password);
    }

    private Map<String, Object> proceedLogin(UserModel user, String password) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), password));
            return handleSuccessfulLogin(user);
        } catch (BadCredentialsException ex) {
            if (ex.getCause() instanceof UsernameNotFoundException) {
                throw ex;
            }
            handleFailedLogin(user);
            throw ex;
        }
    }

    private Map<String, Object> handleSuccessfulLogin(UserModel user) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(MFA.name())) {
            if (unleashUtility.shouldDoMfa(user)) {
                return Map.of(
                        "message", "MFA required",
                        "state_token", generateStateToken(user),
                        "mfa_methods", user.getMfaMethods()
                );
            }
            if (unleash.isEnabled(FORCE_MFA.name())) {
                return Map.of(
                        "message", "MFA required",
                        "state_token", generateStateToken(user),
                        "mfa_methods", Set.of(EMAIL_MFA)
                );
            }
        }
        return accessTokenUtility.generateTokens(user);
    }

    private UUID generateStateToken(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        String encryptedStateTokenKey = getEncryptedStateTokenKey(user);
        Object existingEncryptedStateToken = redisService.get(encryptedStateTokenKey);
        if (existingEncryptedStateToken != null) {
            return genericAesRandomEncryptorDecryptor.decrypt((String) existingEncryptedStateToken, UUID.class);
        }
        UUID stateToken = UUID.randomUUID();
        String encryptedStateTokenMappingKey = genericAesStaticEncryptorDecryptor.encrypt(STATE_TOKEN_MAPPING_PREFIX + stateToken);
        try {
            redisService.save(encryptedStateTokenKey, genericAesRandomEncryptorDecryptor.encrypt(stateToken));
            redisService.save(encryptedStateTokenMappingKey, genericAesRandomEncryptorDecryptor.encrypt(user.getId()));
            return stateToken;
        } catch (Exception ex) {
            redisService.deleteAll(Set.of(encryptedStateTokenKey, encryptedStateTokenMappingKey));
            throw new RuntimeException("Failed to generate state token", ex);
        }
    }

    private String getEncryptedStateTokenKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return genericAesStaticEncryptorDecryptor.encrypt(STATE_TOKEN_PREFIX + user.getId());
    }

    private void handleFailedLogin(UserModel user) {
        user.recordFailedLoginAttempt();
        userRepo.save(user);
    }

    public Map<String, String> logout() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserModel user = getCurrentAuthenticatedUser();
        accessTokenUtility.revokeTokens(Set.of(user));
        return Map.of("message", "Logout successful");
    }

    public Map<String, Object> refreshAccessToken(String refreshToken) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            validateUuid(refreshToken, "Refresh token");
        } catch (SimpleBadRequestException ex) {
            throw new SimpleBadRequestException("Invalid refresh token");
        }
        return accessTokenUtility.refreshAccessToken(refreshToken);
    }

    public Map<String, String> revokeAccessToken() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        accessTokenUtility.revokeAccessToken(getCurrentAuthenticatedUser());
        return Map.of("message", "Access token revoked successfully");
    }
}
