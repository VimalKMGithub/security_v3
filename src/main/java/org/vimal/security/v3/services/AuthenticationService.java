package org.vimal.security.v3.services;

import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.vimal.security.v3.enums.FeatureFlags.*;
import static org.vimal.security.v3.enums.MailType.OTP;
import static org.vimal.security.v3.enums.MailType.SELF_MFA_ENABLE_DISABLE_CONFIRMATION;
import static org.vimal.security.v3.enums.MfaType.AUTHENTICATOR_APP_MFA;
import static org.vimal.security.v3.enums.MfaType.EMAIL_MFA;
import static org.vimal.security.v3.utils.MfaUtility.MFA_METHODS;
import static org.vimal.security.v3.utils.MfaUtility.validateTypeExistence;
import static org.vimal.security.v3.utils.OtpUtility.generateOtp;
import static org.vimal.security.v3.utils.QrUtility.generateQrCode;
import static org.vimal.security.v3.utils.ToggleUtility.TOGGLE_TYPE;
import static org.vimal.security.v3.utils.TotpUtility.*;
import static org.vimal.security.v3.utils.UserUtility.getCurrentAuthenticatedUser;
import static org.vimal.security.v3.utils.ValidationUtility.*;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private static final String STATE_TOKEN_PREFIX = "SECURITY_V3_STATE_TOKEN:";
    private static final String STATE_TOKEN_MAPPING_PREFIX = "SECURITY_V3_STATE_TOKEN_MAPPING:";
    private static final String EMAIL_MFA_OTP_PREFIX = "SECURITY_V3_EMAIL_MFA_OTP:";
    private static final String AUTHENTICATOR_APP_SECRET_PREFIX = "SECURITY_V3_AUTHENTICATOR_APP_SECRET:";
    private final AuthenticationManager authenticationManager;
    private final AccessTokenUtility accessTokenUtility;
    private final RedisService redisService;
    private final UserRepo userRepo;
    private final MailService mailService;
    private final Unleash unleash;
    private final UnleashUtility unleashUtility;
    private final GenericAesStaticEncryptorDecryptor genericAesStaticEncryptorDecryptor;
    private final GenericAesRandomEncryptorDecryptor genericAesRandomEncryptorDecryptor;

    public Map<String, Object> login(String usernameOrEmail,
                                     String password) throws Exception {
        try {
            validateStringIsNonNullAndNotBlank(
                    usernameOrEmail,
                    "Username/email"
            );
            validatePassword(password);
        } catch (SimpleBadRequestException ex) {
            throw new BadCredentialsException("Invalid credentials");
        }
        UserModel user;
        if (EMAIL_PATTERN.matcher(usernameOrEmail)
                .matches()) {
            user = userRepo.findByEmail(genericAesStaticEncryptorDecryptor.encrypt(usernameOrEmail));
            if (user == null) {
                throw new BadCredentialsException("Invalid credentials");
            }
        } else if (USERNAME_PATTERN.matcher(usernameOrEmail)
                .matches()) {
            user = userRepo.findByUsername(genericAesStaticEncryptorDecryptor.encrypt(usernameOrEmail));
            if (user == null) {
                throw new BadCredentialsException("Invalid credentials");
            }
        } else {
            throw new BadCredentialsException("Invalid credentials");
        }
        return proceedLogin(
                user,
                password
        );
    }

    private Map<String, Object> proceedLogin(UserModel user,
                                             String password) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                            user.getUsername(),
                            password
                    )
            );
            return handleSuccessfulLogin(user);
        } catch (BadCredentialsException ex) {
            if (ex.getCause() instanceof UsernameNotFoundException) {
                throw ex;
            }
            handleFailedLogin(user);
            throw ex;
        }
    }

    private Map<String, Object> handleSuccessfulLogin(UserModel user) throws Exception {
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

    private String generateStateToken(UserModel user) throws Exception {
        String encryptedStateTokenKey = getEncryptedStateTokenKey(user);
        String existingEncryptedStateToken = redisService.get(encryptedStateTokenKey);
        if (existingEncryptedStateToken != null) {
            return genericAesRandomEncryptorDecryptor.decrypt(existingEncryptedStateToken);
        }
        String stateToken = UUID.randomUUID().toString();
        String encryptedStateTokenMappingKey = genericAesStaticEncryptorDecryptor.encrypt(STATE_TOKEN_MAPPING_PREFIX + stateToken);
        try {
            redisService.save(
                    encryptedStateTokenKey,
                    genericAesRandomEncryptorDecryptor.encrypt(stateToken)
            );
            redisService.save(
                    encryptedStateTokenMappingKey,
                    genericAesRandomEncryptorDecryptor.encrypt(user.getId().toString())
            );
            return stateToken;
        } catch (Exception ex) {
            redisService.deleteAll(Set.of(
                            encryptedStateTokenKey,
                            encryptedStateTokenMappingKey
                    )
            );
            throw new RuntimeException("Failed to generate state token", ex);
        }
    }

    private String getEncryptedStateTokenKey(UserModel user) throws Exception {
        return getEncryptedStateTokenKey(user.getId());
    }

    private String getEncryptedStateTokenKey(UUID userId) throws Exception {
        return getEncryptedStateTokenKey(userId.toString());
    }

    private String getEncryptedStateTokenKey(String userId) throws Exception {
        return genericAesStaticEncryptorDecryptor.encrypt(STATE_TOKEN_PREFIX + userId);
    }

    private void handleFailedLogin(UserModel user) {
        user.recordFailedLoginAttempt();
        userRepo.save(user);
    }

    public Map<String, String> logout() throws Exception {
        accessTokenUtility.revokeTokens(Set.of(getCurrentAuthenticatedUser()));
        return Map.of("message", "Logout successful");
    }

    public Map<String, Object> refreshAccessToken(String refreshToken) throws Exception {
        try {
            validateUuid(
                    refreshToken,
                    "Refresh token"
            );
        } catch (SimpleBadRequestException ex) {
            throw new SimpleBadRequestException("Invalid refresh token");
        }
        return accessTokenUtility.refreshAccessToken(refreshToken);
    }

    public Map<String, String> revokeAccessToken() throws Exception {
        accessTokenUtility.revokeAccessToken(getCurrentAuthenticatedUser());
        return Map.of("message", "Access token revoked successfully");
    }

    public Map<String, String> revokeRefreshToken(String refreshToken) throws Exception {
        try {
            validateUuid(
                    refreshToken,
                    "Refresh token"
            );
        } catch (SimpleBadRequestException ex) {
            throw new SimpleBadRequestException("Invalid refresh token");
        }
        accessTokenUtility.revokeRefreshToken(refreshToken);
        return Map.of("message", "Refresh token revoked successfully");
    }

    public ResponseEntity<Object> requestToToggleMfa(String type,
                                                     String toggle) throws Exception {
        boolean toggleEnabled = validateToggle(toggle);
        UserModel user = getCurrentAuthenticatedUser();
        return proceedRequestToToggleMfa(
                user,
                validateType(type, user, toggleEnabled),
                toggleEnabled
        );
    }

    private boolean validateToggle(String toggle) {
        if (!TOGGLE_TYPE.contains(toggle.toLowerCase())) {
            throw new SimpleBadRequestException("Unsupported toggle type: " + toggle + ". Supported values: " + TOGGLE_TYPE);
        }
        return toggle.equalsIgnoreCase("enable");
    }

    private MfaType validateType(String type,
                                 UserModel user,
                                 boolean toggleEnabled) {
        validateTypeExistence(type);
        unleashUtility.isMfaEnabledGlobally();
        MfaType mfaType = MfaType.valueOf(type.toUpperCase());
        if (!unleash.isEnabled(mfaType.toFeatureFlag()
                .name())) {
            throw new ServiceUnavailableException(type + " Mfa is disabled globally");
        }
        boolean hasMfaType = user.hasMfaMethod(mfaType);
        if (toggleEnabled &&
                hasMfaType) {
            throw new SimpleBadRequestException(type + " Mfa is already enabled");
        }
        if (!toggleEnabled &&
                !hasMfaType) {
            throw new SimpleBadRequestException(type + " Mfa is already disabled");
        }
        return mfaType;
    }

    private ResponseEntity<Object> proceedRequestToToggleMfa(UserModel user,
                                                             MfaType type,
                                                             boolean toggleEnabled) throws Exception {
        if (toggleEnabled) {
            switch (type) {
                case EMAIL_MFA -> {
                    mailService.sendEmailAsync(
                            genericAesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                            "Otp to enable email Mfa",
                            generateOtpForEmailMfa(user),
                            OTP
                    );
                    return ResponseEntity.ok(Map.of("message", "Otp sent to your registered email address. Please check your email to continue"));
                }
                case AUTHENTICATOR_APP_MFA -> {
                    return ResponseEntity.ok()
                            .contentType(MediaType.IMAGE_PNG)
                            .body(generateQrCodeForAuthenticatorApp(user));
                }
            }
        } else {
            switch (type) {
                case EMAIL_MFA -> {
                    mailService.sendEmailAsync(
                            genericAesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                            "Otp to disable email Mfa",
                            generateOtpForEmailMfa(user),
                            OTP
                    );
                    return ResponseEntity.ok(Map.of("message", "Otp sent to your registered email address. Please check your email to continue"));
                }
                case AUTHENTICATOR_APP_MFA -> {
                    return ResponseEntity.ok(Map.of("message", "Please proceed to verify Totp"));
                }
            }
        }
        throw new SimpleBadRequestException("Unsupported Mfa type: " + type + ". Supported types: " + MFA_METHODS);
    }

    private String generateOtpForEmailMfa(UserModel user) throws Exception {
        String otp = generateOtp();
        redisService.save(
                getEncryptedEmailMfaOtpKey(user),
                genericAesRandomEncryptorDecryptor.encrypt(otp)
        );
        return otp;
    }

    private String getEncryptedEmailMfaOtpKey(UserModel user) throws Exception {
        return getEncryptedEmailMfaOtpKey(user.getId());
    }

    private String getEncryptedEmailMfaOtpKey(UUID userId) throws Exception {
        return getEncryptedEmailMfaOtpKey(userId.toString());
    }

    private String getEncryptedEmailMfaOtpKey(String userId) throws Exception {
        return genericAesStaticEncryptorDecryptor.encrypt(EMAIL_MFA_OTP_PREFIX + userId);
    }

    private byte[] generateQrCodeForAuthenticatorApp(UserModel user) throws Exception {
        return generateQrCode(generateTotpUrl(
                        "God Level Security",
                        user.getUsername(),
                        generateAuthenticatorAppSecret(user)
                )
        );
    }

    private String generateAuthenticatorAppSecret(UserModel user) throws Exception {
        String secret = generateBase32Secret();
        redisService.save(
                getEncryptedSecretKey(user),
                genericAesRandomEncryptorDecryptor.encrypt(secret)
        );
        return secret;
    }

    private String getEncryptedSecretKey(UserModel user) throws Exception {
        return getEncryptedSecretKey(user.getId());
    }

    private String getEncryptedSecretKey(UUID userId) throws Exception {
        return getEncryptedSecretKey(userId.toString());
    }

    private String getEncryptedSecretKey(String userId) throws Exception {
        return genericAesStaticEncryptorDecryptor.encrypt(AUTHENTICATOR_APP_SECRET_PREFIX + userId);
    }

    public Map<String, String> verifyToggleMfa(String type,
                                               String toggle,
                                               String otpTotp) throws Exception {
        boolean toggleEnabled = validateToggle(toggle);
        UserModel user = getCurrentAuthenticatedUser();
        return proceedToVerifyToggleMfa(
                user,
                validateType(type, user, toggleEnabled),
                toggleEnabled,
                otpTotp
        );
    }

    private Map<String, String> proceedToVerifyToggleMfa(UserModel user,
                                                         MfaType type,
                                                         boolean toggleEnabled,
                                                         String otpTotp) throws Exception {
        if (toggleEnabled) {
            switch (type) {
                case EMAIL_MFA -> {
                    return verifyOtpToToggleEmailMfa(
                            user,
                            otpTotp,
                            true
                    );
                }
                case AUTHENTICATOR_APP_MFA -> {
                    return verifyTotpToEnableAuthenticatorAppMfa(
                            user,
                            otpTotp
                    );
                }
            }
        } else {
            switch (type) {
                case EMAIL_MFA -> {
                    return verifyOtpToToggleEmailMfa(
                            user,
                            otpTotp,
                            false
                    );
                }
                case AUTHENTICATOR_APP_MFA -> {
                    return verifyTotpToDisableAuthenticatorAppMfa(
                            user,
                            otpTotp
                    );
                }
            }
        }
        throw new SimpleBadRequestException("Unsupported Mfa type: " + type + ". Supported types: " + MFA_METHODS);
    }

    private Map<String, String> verifyOtpToToggleEmailMfa(UserModel user,
                                                          String otp,
                                                          boolean toggle) throws Exception {
        validateOtpTotp(otp);
        String encryptedEmailMfaOtpKey = getEncryptedEmailMfaOtpKey(user);
        String encryptedOtp = redisService.get(encryptedEmailMfaOtpKey);
        if (encryptedOtp != null) {
            if (genericAesRandomEncryptorDecryptor.decrypt(encryptedOtp)
                    .equals(otp)) {
                try {
                    redisService.delete(encryptedEmailMfaOtpKey);
                } catch (Exception ignored) {
                }
                user = userRepo.findById(user.getId())
                        .orElseThrow(() -> new SimpleBadRequestException("Invalid user"));
                if (toggle) {
                    user.addMfaMethod(EMAIL_MFA);
                } else {
                    user.removeMfaMethod(EMAIL_MFA);
                }
                user.recordUpdation(genericAesRandomEncryptorDecryptor.encrypt("SELF"));
                accessTokenUtility.revokeTokens(Set.of(user));
                userRepo.save(user);
                emailConfirmationOnMfaToggle(
                        user,
                        EMAIL_MFA,
                        toggle
                );
                if (toggle) {
                    return Map.of("message", "Email Mfa enabled successfully. Please log in again to continue");
                } else {
                    return Map.of("message", "Email Mfa disabled successfully. Please log in again to continue");
                }
            }
            throw new SimpleBadRequestException("Invalid Otp");
        }
        throw new SimpleBadRequestException("Invalid Otp");
    }

    private void validateOtpTotp(String otpTotp) {
        try {
            validateOtp(
                    otpTotp,
                    "Otp/Totp"
            );
        } catch (SimpleBadRequestException ex) {
            throw new SimpleBadRequestException("Invalid Otp/Totp");
        }
    }

    private void emailConfirmationOnMfaToggle(UserModel user,
                                              MfaType type,
                                              boolean toggle) throws Exception {
        if (unleash.isEnabled(EMAIL_CONFIRMATION_ON_SELF_MFA_ENABLE_DISABLE.name())) {
            String action = toggle ? "enabled" : "disabled";
            mailService.sendEmailAsync(
                    genericAesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                    "Mfa " + action + " confirmation",
                    "Your " + type + " Mfa has been " + action,
                    SELF_MFA_ENABLE_DISABLE_CONFIRMATION
            );
        }
    }

    private Map<String, String> verifyTotpToEnableAuthenticatorAppMfa(UserModel user,
                                                                      String totp) throws Exception {
        validateOtpTotp(totp);
        String encryptedSecretKey = getEncryptedSecretKey(user);
        String encryptedSecret = redisService.get(encryptedSecretKey);
        if (encryptedSecret != null) {
            String secret = genericAesRandomEncryptorDecryptor.decrypt(encryptedSecret);
            if (verifyTotp(
                    secret,
                    totp
            )) {
                try {
                    redisService.delete(encryptedSecretKey);
                } catch (Exception ignored) {
                }
                user = userRepo.findById(user.getId())
                        .orElseThrow(() -> new SimpleBadRequestException("Invalid user"));
                user.addMfaMethod(AUTHENTICATOR_APP_MFA);
                user.setAuthAppSecret(genericAesRandomEncryptorDecryptor.encrypt(secret));
                user.recordUpdation(genericAesRandomEncryptorDecryptor.encrypt("SELF"));
                accessTokenUtility.revokeTokens(Set.of(user));
                userRepo.save(user);
                emailConfirmationOnMfaToggle(
                        user,
                        AUTHENTICATOR_APP_MFA,
                        true
                );
                return Map.of("message", "Authenticator app Mfa enabled successfully. Please log in again to continue");
            }
            throw new SimpleBadRequestException("Invalid Totp");
        }
        throw new SimpleBadRequestException("Invalid Totp");
    }

    private Map<String, String> verifyTotpToDisableAuthenticatorAppMfa(UserModel user,
                                                                       String totp) throws Exception {
        validateOtpTotp(totp);
        user = userRepo.findById(user.getId())
                .orElseThrow(() -> new SimpleBadRequestException("Invalid user"));
        if (!verifyTotp(
                genericAesRandomEncryptorDecryptor.decrypt(user.getAuthAppSecret()),
                totp
        )) {
            throw new SimpleBadRequestException("Invalid Totp");
        }
        user.removeMfaMethod(AUTHENTICATOR_APP_MFA);
        user.setAuthAppSecret(null);
        user.recordUpdation(genericAesRandomEncryptorDecryptor.encrypt("SELF"));
        accessTokenUtility.revokeTokens(Set.of(user));
        userRepo.save(user);
        emailConfirmationOnMfaToggle(
                user,
                AUTHENTICATOR_APP_MFA,
                false
        );
        return Map.of("message", "Authenticator app Mfa disabled successfully. Please log in again to continue");
    }

    public Map<String, String> requestToLoginMfa(String type,
                                                 String stateToken) throws Exception {
        validateTypeExistence(type);
        unleashUtility.isMfaEnabledGlobally();
        try {
            validateUuid(
                    stateToken,
                    "State token"
            );
        } catch (SimpleBadRequestException ex) {
            throw new SimpleBadRequestException("Invalid state token");
        }
        UserModel user = getUser(stateToken);
        switch (MfaType.valueOf(type.toUpperCase())) {
            case EMAIL_MFA -> {
                if (user.getMfaMethods().isEmpty()) {
                    if (!unleash.isEnabled(FORCE_MFA.name())) {
                        throw new SimpleBadRequestException("Email Mfa is not enabled");
                    }
                    return sendEmailOtpToLoginMfa(user);
                } else if (user.hasMfaMethod(EMAIL_MFA)) {
                    if (!unleash.isEnabled(MFA_EMAIL.name())) {
                        throw new ServiceUnavailableException("Email Mfa is disabled globally");
                    }
                    return sendEmailOtpToLoginMfa(user);
                } else {
                    throw new SimpleBadRequestException("Email Mfa is not enabled");
                }
            }
            case AUTHENTICATOR_APP_MFA -> {
                if (!unleash.isEnabled(MFA_AUTHENTICATOR_APP.name())) {
                    throw new ServiceUnavailableException("Authenticator app Mfa is disabled globally");
                }
                if (!user.hasMfaMethod(AUTHENTICATOR_APP_MFA)) {
                    throw new SimpleBadRequestException("Authenticator app Mfa is not enabled");
                }
                return Map.of("message", "Please proceed to verify Totp");
            }
        }
        throw new SimpleBadRequestException("Unsupported Mfa type: " + type + ". Supported types: " + MFA_METHODS);
    }

    private UserModel getUser(String stateToken) throws Exception {
        return userRepo.findById(UUID.fromString(getUserIdFromEncryptedStateTokenMappingKey(getEncryptedStateTokenMappingKey(stateToken))))
                .orElseThrow(() -> new SimpleBadRequestException("Invalid state token"));
    }

    private String getUserIdFromEncryptedStateTokenMappingKey(String encryptedStateTokenMappingKey) throws Exception {
        String encryptedUserId = redisService.get(encryptedStateTokenMappingKey);
        if (encryptedUserId != null) {
            return genericAesRandomEncryptorDecryptor.decrypt(encryptedUserId);
        }
        throw new SimpleBadRequestException("Invalid state token");
    }

    private String getEncryptedStateTokenMappingKey(String stateToken) throws Exception {
        return genericAesStaticEncryptorDecryptor.encrypt(STATE_TOKEN_MAPPING_PREFIX + stateToken);
    }

    private Map<String, String> sendEmailOtpToLoginMfa(UserModel user) throws Exception {
        mailService.sendEmailAsync(
                genericAesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                "Otp to verify email Mfa to login",
                generateOtpForEmailMfa(user),
                OTP
        );
        return Map.of("message", "Otp sent to your registered email address. Please check your email to continue");
    }

    public Map<String, Object> verifyMfaToLogin(String type,
                                                String stateToken,
                                                String otpTotp) throws Exception {
        validateTypeExistence(type);
        unleashUtility.isMfaEnabledGlobally();
        try {
            validateUuid(
                    stateToken,
                    "State token"
            );
            validateOtp(
                    otpTotp,
                    "Otp/Totp"
            );
        } catch (SimpleBadRequestException ex) {
            throw new SimpleBadRequestException("Invalid Otp/Totp or state token");
        }
        String encryptedStateTokenMappingKey = getEncryptedStateTokenMappingKey(stateToken);
        UserModel user = userRepo.findById(UUID.fromString(getUserIdFromEncryptedStateTokenMappingKey(encryptedStateTokenMappingKey)))
                .orElseThrow(() -> new SimpleBadRequestException("Invalid state token"));
        switch (MfaType.valueOf(type.toUpperCase())) {
            case EMAIL_MFA -> {
                if (user.getMfaMethods().isEmpty()) {
                    if (!unleash.isEnabled(FORCE_MFA.name())) {
                        throw new SimpleBadRequestException("Email Mfa is not enabled");
                    }
                    return verifyEmailOtpToLogin(
                            user,
                            otpTotp,
                            encryptedStateTokenMappingKey
                    );
                } else if (user.hasMfaMethod(EMAIL_MFA)) {
                    if (!unleash.isEnabled(MFA_EMAIL.name())) {
                        throw new ServiceUnavailableException("Email Mfa is disabled globally");
                    }
                    return verifyEmailOtpToLogin(
                            user,
                            otpTotp,
                            encryptedStateTokenMappingKey
                    );
                } else {
                    throw new SimpleBadRequestException("Email Mfa is not enabled");
                }
            }
            case AUTHENTICATOR_APP_MFA -> {
                if (!unleash.isEnabled(MFA_AUTHENTICATOR_APP.name())) {
                    throw new ServiceUnavailableException("Authenticator app Mfa is disabled globally");
                }
                if (!user.hasMfaMethod(AUTHENTICATOR_APP_MFA)) {
                    throw new SimpleBadRequestException("Authenticator app Mfa is not enabled");
                }
                return verifyAuthenticatorAppTotpToLogin(
                        user,
                        otpTotp,
                        encryptedStateTokenMappingKey
                );
            }
        }
        throw new SimpleBadRequestException("Unsupported Mfa type: " + type + ". Supported types: " + MFA_METHODS);
    }

    private Map<String, Object> verifyEmailOtpToLogin(UserModel user,
                                                      String otp,
                                                      String encryptedStateTokenMappingKey) throws Exception {
        checkLockedStatus(user);
        String encryptedEmailMfaOtpKey = getEncryptedEmailMfaOtpKey(user);
        String encryptedOtp = redisService.get(encryptedEmailMfaOtpKey);
        if (encryptedOtp != null) {
            if (genericAesRandomEncryptorDecryptor.decrypt(encryptedOtp)
                    .equals(otp)
            ) {
                try {
                    redisService.deleteAll(Set.of(
                                    getEncryptedStateTokenKey(user),
                                    encryptedStateTokenMappingKey,
                                    encryptedEmailMfaOtpKey
                            )
                    );
                } catch (Exception ignored) {
                }
                return accessTokenUtility.generateTokens(user);
            }
            handleFailedMfaLoginAttempt(user);
            throw new SimpleBadRequestException("Invalid Otp");
        }
        handleFailedMfaLoginAttempt(user);
        throw new SimpleBadRequestException("Invalid Otp");
    }

    private void checkLockedStatus(UserModel user) {
        if (user.isAccountLocked() &&
                user.getLockedAt()
                        .plus(
                                1,
                                ChronoUnit.DAYS
                        )
                        .isAfter(Instant.now())
        ) {
            throw new LockedException("Account is locked due to too many failed mfa attempts. Please try again later");
        }
    }

    private void handleFailedMfaLoginAttempt(UserModel user) {
        user.recordFailedMfaAttempt();
        userRepo.save(user);
    }

    private Map<String, Object> verifyAuthenticatorAppTotpToLogin(UserModel user,
                                                                  String totp,
                                                                  String encryptedStateTokenMappingKey) throws Exception {
        checkLockedStatus(user);
        if (verifyTotp(
                genericAesRandomEncryptorDecryptor.decrypt(user.getAuthAppSecret()),
                totp
        )) {
            try {
                redisService.deleteAll(Set.of(
                                getEncryptedStateTokenKey(user),
                                encryptedStateTokenMappingKey
                        )
                );
            } catch (Exception ignored) {
            }
            return accessTokenUtility.generateTokens(user);
        }
        handleFailedMfaLoginAttempt(user);
        throw new SimpleBadRequestException("Invalid Totp");
    }
}
