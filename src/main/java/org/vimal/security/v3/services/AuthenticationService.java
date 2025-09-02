package org.vimal.security.v3.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.zxing.WriterException;
import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.jose4j.lang.JoseException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.vimal.security.v3.encryptordecryptors.GenericAesRandomEncryptorDecryptor;
import org.vimal.security.v3.encryptordecryptors.GenericAesStaticEncryptorDecryptor;
import org.vimal.security.v3.enums.MfaType;
import org.vimal.security.v3.exceptions.ServiceUnavailableException;
import org.vimal.security.v3.exceptions.SimpleBadRequestException;
import org.vimal.security.v3.models.UserModel;
import org.vimal.security.v3.repos.UserRepo;
import org.vimal.security.v3.utils.AccessTokenUtility;
import org.vimal.security.v3.utils.UnleashUtility;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.vimal.security.v3.enums.FeatureFlags.FORCE_MFA;
import static org.vimal.security.v3.enums.FeatureFlags.MFA;
import static org.vimal.security.v3.enums.MailType.OTP;
import static org.vimal.security.v3.enums.MfaType.EMAIL_MFA;
import static org.vimal.security.v3.utils.MfaUtility.MFA_METHODS;
import static org.vimal.security.v3.utils.MfaUtility.validateTypeExistence;
import static org.vimal.security.v3.utils.OtpUtility.generateOtp;
import static org.vimal.security.v3.utils.QrUtility.generateQRCode;
import static org.vimal.security.v3.utils.TotpUtility.generateBase32Secret;
import static org.vimal.security.v3.utils.TotpUtility.generateTotpUrl;
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
                        "message", "Mfa required",
                        "state_token", generateStateToken(user),
                        "mfa_methods", user.getMfaMethods()
                );
            }
            if (unleash.isEnabled(FORCE_MFA.name())) {
                return Map.of(
                        "message", "Mfa required",
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

    public Map<String, String> revokeRefreshToken(String refreshToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            validateUuid(refreshToken, "Refresh token");
        } catch (SimpleBadRequestException ex) {
            throw new SimpleBadRequestException("Invalid refresh token");
        }
        accessTokenUtility.revokeRefreshToken(refreshToken);
        return Map.of("message", "Refresh token revoked successfully");
    }

    public ResponseEntity<Object> requestToToggleMfa(String type, String toggle) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException, WriterException {
        boolean toggleEnabled = validateToggle(toggle);
        UserModel user = getCurrentAuthenticatedUser();
        return proceedRequestToToggleMfa(user, validateType(type, user, toggleEnabled), toggleEnabled);
    }

    private boolean validateToggle(String toggle) {
        if (!TOGGLE_TYPE.contains(toggle.toLowerCase())) {
            throw new SimpleBadRequestException("Unsupported toggle type: " + toggle + ". Supported values: " + TOGGLE_TYPE);
        }
        return toggle.equalsIgnoreCase("enable");
    }

    private MfaType validateType(String type, UserModel user, boolean toggleEnabled) {
        validateTypeExistence(type);
        unleashUtility.isMfaEnabledGlobally();
        MfaType mfaType = MfaType.valueOf(type.toUpperCase());
        if (!unleash.isEnabled(mfaType.toFeatureFlag().name())) {
            throw new ServiceUnavailableException(type + " Mfa is disabled globally");
        }
        boolean hasMFAType = user.hasMfaMethod(mfaType);
        if (toggleEnabled && hasMFAType) {
            throw new SimpleBadRequestException(type + " Mfa is already enabled");
        }
        if (!toggleEnabled && !hasMFAType) {
            throw new SimpleBadRequestException(type + " Mfa is already disabled");
        }
        return mfaType;
    }

    private ResponseEntity<Object> proceedRequestToToggleMfa(UserModel user, MfaType type, boolean toggleEnabled) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException, WriterException {
        if (toggleEnabled) {
            switch (type) {
                case EMAIL_MFA -> {
                    mailService.sendEmailAsync(user.getEmail(), "Otp to enable email Mfa", generateOtpForEmailMfa(user), OTP);
                    return ResponseEntity.ok(Map.of("message", "Otp sent to your registered email address. Please check your email to continue"));
                }
                case AUTHENTICATOR_APP_MFA -> {
                    return ResponseEntity.ok().contentType(MediaType.IMAGE_PNG).body(generateQrCodeForAuthenticatorApp(user));
                }
            }
        } else {
            switch (type) {
                case EMAIL_MFA -> {
                    mailService.sendEmailAsync(user.getEmail(), "Otp to disable email MFA", generateOtpForEmailMfa(user), OTP);
                    return ResponseEntity.ok(Map.of("message", "Otp sent to your registered email address. Please check your email to continue"));
                }
                case AUTHENTICATOR_APP_MFA -> {
                    return ResponseEntity.ok(Map.of("message", "Please proceed to verify Totp"));
                }
            }
        }
        throw new SimpleBadRequestException("Unsupported Mfa type: " + type + ". Supported types: " + MFA_METHODS);
    }

    private String generateOtpForEmailMfa(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        String otp = generateOtp();
        redisService.save(getEncryptedEmailMfaOtpKey(user), genericAesRandomEncryptorDecryptor.encrypt(otp));
        return otp;
    }

    private String getEncryptedEmailMfaOtpKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return genericAesStaticEncryptorDecryptor.encrypt(EMAIL_MFA_OTP_PREFIX + user.getId());
    }

    private byte[] generateQrCodeForAuthenticatorApp(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException, WriterException {
        return generateQRCode(generateTotpUrl("God Level Security", user.getUsername(), generateAuthenticatorAppSecret(user)));
    }

    private String generateAuthenticatorAppSecret(UserModel user) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        String secret = generateBase32Secret();
        redisService.save(getEncryptedSecretKey(user), genericAesRandomEncryptorDecryptor.encrypt(secret));
        return secret;
    }

    private String getEncryptedSecretKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return genericAesStaticEncryptorDecryptor.encrypt(AUTHENTICATOR_APP_SECRET_PREFIX + user.getId());
    }
}
