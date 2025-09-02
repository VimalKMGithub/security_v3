package org.vimal.security.v3.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v3.dtos.*;
import org.vimal.security.v3.encryptordecryptors.GenericAesRandomEncryptorDecryptor;
import org.vimal.security.v3.encryptordecryptors.GenericAesStaticEncryptorDecryptor;
import org.vimal.security.v3.enums.MfaType;
import org.vimal.security.v3.exceptions.ServiceUnavailableException;
import org.vimal.security.v3.exceptions.SimpleBadRequestException;
import org.vimal.security.v3.models.UserModel;
import org.vimal.security.v3.repos.UserRepo;
import org.vimal.security.v3.utils.AccessTokenUtility;
import org.vimal.security.v3.utils.MapperUtility;
import org.vimal.security.v3.utils.UnleashUtility;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static org.vimal.security.v3.enums.FeatureFlags.*;
import static org.vimal.security.v3.enums.MailType.*;
import static org.vimal.security.v3.enums.MfaType.AUTHENTICATOR_APP_MFA;
import static org.vimal.security.v3.enums.MfaType.EMAIL_MFA;
import static org.vimal.security.v3.utils.EmailUtility.normalizeEmail;
import static org.vimal.security.v3.utils.MfaUtility.MFA_METHODS;
import static org.vimal.security.v3.utils.MfaUtility.validateTypeExistence;
import static org.vimal.security.v3.utils.OtpUtility.generateOtp;
import static org.vimal.security.v3.utils.TotpUtility.verifyTotp;
import static org.vimal.security.v3.utils.UserUtility.getCurrentAuthenticatedUser;
import static org.vimal.security.v3.utils.ValidationUtility.*;

@Service
@RequiredArgsConstructor
public class UserService {
    private static final String EMAIL_VERIFICATION_TOKEN_PREFIX = "SECURITY_V3_EMAIL_VERIFICATION_TOKEN:";
    private static final String EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX = "SECURITY_V3_EMAIL_VERIFICATION_TOKEN_MAPPING:";
    private static final String FORGOT_PASSWORD_OTP_PREFIX = "SECURITY_V3_FORGOT_PASSWORD_OTP:";
    private static final String EMAIL_CHANGE_OTP_FOR_NEW_EMAIL_PREFIX = "SECURITY_V3_EMAIL_CHANGE_OTP_FOR_NEW_EMAIL:";
    private static final String EMAIL_CHANGE_OTP_FOR_OLD_EMAIL_PREFIX = "SECURITY_V3_EMAIL_CHANGE_OTP_FOR_OLD_EMAIL:";
    private static final String EMAIL_STORE_PREFIX = "SECURITY_V3_EMAIL_STORE:";
    private static final String EMAIL_OTP_TO_DELETE_ACCOUNT_PREFIX = "SECURITY_V3_EMAIL_OTP_TO_DELETE_ACCOUNT:";
    private static final String EMAIL_OTP_FOR_PASSWORD_CHANGE_PREFIX = "SECURITY_V3_EMAIL_OTP_FOR_PASSWORD_CHANGE:";
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final MailService mailService;
    private final RedisService redisService;
    private final Unleash unleash;
    private final AccessTokenUtility accessTokenUtility;
    private final MapperUtility mapperUtility;
    private final UnleashUtility unleashUtility;
    private final GenericAesStaticEncryptorDecryptor genericAesStaticEncryptorDecryptor;
    private final GenericAesRandomEncryptorDecryptor genericAesRandomEncryptorDecryptor;

    public ResponseEntity<Map<String, Object>> register(RegistrationDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(REGISTRATION_ENABLED.name())) {
            Set<String> invalidInputs = validateInputs(dto);
            if (!invalidInputs.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
            }
            if (userRepo.existsByUsername(genericAesStaticEncryptorDecryptor.encrypt(dto.getUsername()))) {
                throw new SimpleBadRequestException("Username: '" + dto.getUsername() + "' is already taken");
            }
            if (userRepo.existsByEmail(genericAesStaticEncryptorDecryptor.encrypt(dto.getEmail()))) {
                throw new SimpleBadRequestException("Email: '" + dto.getEmail() + "' is already taken");
            }
            String normalizedEmail = normalizeEmail(dto.getEmail());
            if (userRepo.existsByRealEmail(genericAesStaticEncryptorDecryptor.encrypt(normalizedEmail))) {
                throw new SimpleBadRequestException("Alias version of email: '" + dto.getEmail() + "' is already taken");
            }
            UserModel user = toUserModel(dto, normalizedEmail);
            boolean shouldVerifyRegisteredEmail = unleash.isEnabled(REGISTRATION_EMAIL_VERIFICATION.name());
            user.setEmailVerified(!shouldVerifyRegisteredEmail);
            Map<String, Object> response = new HashMap<>();
            user = userRepo.save(user);
            if (shouldVerifyRegisteredEmail) {
                mailService.sendEmailAsync(dto.getEmail(), "Email verification link after registration", "https://godLevelSecurity.com/verifyEmailAfterRegistration?token=" + generateEmailVerificationToken(user), LINK);
                response.put("message", "Registration successful. Please check your email for verification link");
            } else {
                response.put("message", "Registration successful");
            }
            response.put("user", mapperUtility.toUserSummaryDto(user));
            return ResponseEntity.ok(response);
        }
        throw new ServiceUnavailableException("Registration is currently disabled. Please try again later");
    }

    private UserModel toUserModel(RegistrationDto dto, String normalizedEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return UserModel.builder()
                .username(genericAesStaticEncryptorDecryptor.encrypt(dto.getUsername()))
                .email(genericAesStaticEncryptorDecryptor.encrypt(dto.getEmail()))
                .realEmail(genericAesStaticEncryptorDecryptor.encrypt(normalizedEmail))
                .password(passwordEncoder.encode(dto.getPassword()))
                .firstName(dto.getFirstName())
                .middleName(dto.getMiddleName())
                .lastName(dto.getLastName())
                .createdBy(genericAesRandomEncryptorDecryptor.encrypt("SELF"))
                .updatedBy(genericAesRandomEncryptorDecryptor.encrypt("SELF"))
                .build();
    }

    private UUID generateEmailVerificationToken(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        String encryptedEmailVerificationTokenKey = getEncryptedEmailVerificationTokenKey(user);
        Object existingEncryptedEmailVerificationToken = redisService.get(encryptedEmailVerificationTokenKey);
        if (existingEncryptedEmailVerificationToken != null) {
            return genericAesRandomEncryptorDecryptor.decrypt((String) existingEncryptedEmailVerificationToken, UUID.class);
        }
        UUID emailVerificationToken = UUID.randomUUID();
        String encryptedEmailVerificationTokenMappingKey = genericAesStaticEncryptorDecryptor.encrypt(EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX + emailVerificationToken);
        try {
            redisService.save(encryptedEmailVerificationTokenKey, genericAesRandomEncryptorDecryptor.encrypt(emailVerificationToken));
            redisService.save(encryptedEmailVerificationTokenMappingKey, genericAesRandomEncryptorDecryptor.encrypt(user.getId()));
            return emailVerificationToken;
        } catch (Exception ex) {
            redisService.deleteAll(Set.of(encryptedEmailVerificationTokenKey, encryptedEmailVerificationTokenMappingKey));
            throw new RuntimeException("Failed to generate email verification token", ex);
        }
    }

    private String getEncryptedEmailVerificationTokenKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return genericAesStaticEncryptorDecryptor.encrypt(EMAIL_VERIFICATION_TOKEN_PREFIX + user.getId());
    }

    public UserSummaryDto getSelfDetails() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserModel user = userRepo.findById(getCurrentAuthenticatedUser().getId()).orElseThrow(() -> new SimpleBadRequestException("Invalid user"));
        return mapperUtility.toUserSummaryDto(user);
    }

    public Map<String, Object> verifyEmail(String emailVerificationToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            validateUuid(emailVerificationToken, "Email verification token");
        } catch (SimpleBadRequestException ex) {
            throw new SimpleBadRequestException("Invalid email verification token");
        }
        String encryptedEmailVerificationTokenMappingKey = getEncryptedEmailVerificationTokenMappingKey(emailVerificationToken);
        UserModel user = userRepo.findById(getUserIdFromEncryptedEmailVerificationTokenMappingKey(encryptedEmailVerificationTokenMappingKey)).orElseThrow(() -> new SimpleBadRequestException("Invalid email verification token"));
        if (user.isEmailVerified()) {
            throw new SimpleBadRequestException("Email is already verified");
        }
        user.setEmailVerified(true);
        user.recordUpdation(genericAesRandomEncryptorDecryptor.encrypt("SELF"));
        try {
            redisService.deleteAll(Set.of(getEncryptedEmailVerificationTokenKey(user), encryptedEmailVerificationTokenMappingKey));
        } catch (Exception ignored) {
        }
        return Map.of(
                "message", "Email verification successful",
                "user", mapperUtility.toUserSummaryDto(userRepo.save(user))
        );
    }

    private String getEncryptedEmailVerificationTokenMappingKey(String emailVerificationToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return genericAesStaticEncryptorDecryptor.encrypt(EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX + emailVerificationToken);
    }

    private UUID getUserIdFromEncryptedEmailVerificationTokenMappingKey(String encryptedEmailVerificationTokenMappingKey) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        Object encryptedUserId = redisService.get(encryptedEmailVerificationTokenMappingKey);
        if (encryptedUserId != null) {
            return genericAesRandomEncryptorDecryptor.decrypt((String) encryptedUserId, UUID.class);
        }
        throw new SimpleBadRequestException("Invalid email verification token");
    }

    public Map<String, String> resendEmailVerificationLink(String usernameOrEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(RESEND_REGISTRATION_EMAIL_VERIFICATION.name())) {
            return proceedResendEmailVerificationLink(getUserByUsernameOrEmail(usernameOrEmail));
        }
        throw new ServiceUnavailableException("Resending email verification link is currently disabled. Please try again later");
    }

    private Map<String, String> proceedResendEmailVerificationLink(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (user.isEmailVerified()) {
            throw new SimpleBadRequestException("Email is already verified");
        }
        mailService.sendEmailAsync(user.getEmail(), "Resending email verification link after registration", "https://godLevelSecurity.com/verifyEmailAfterRegistration?token=" + generateEmailVerificationToken(user), LINK);
        return Map.of("message", "Email verification link resent successfully. Please check your email");
    }

    private UserModel getUserByUsernameOrEmail(String usernameOrEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            validateStringIsNonNullAndNotBlank(usernameOrEmail, "Username/email");
        } catch (SimpleBadRequestException ex) {
            throw new SimpleBadRequestException("Invalid username/email");
        }
        UserModel user;
        if (USERNAME_PATTERN.matcher(usernameOrEmail).matches()) {
            user = userRepo.findByUsername(genericAesStaticEncryptorDecryptor.encrypt(usernameOrEmail));
            if (user == null) {
                throw new SimpleBadRequestException("Invalid username");
            }
        } else if (EMAIL_PATTERN.matcher(usernameOrEmail).matches()) {
            user = userRepo.findByEmail(genericAesStaticEncryptorDecryptor.encrypt(usernameOrEmail));
            if (user == null) {
                throw new SimpleBadRequestException("Invalid email");
            }
        } else {
            throw new SimpleBadRequestException("Invalid username/email");
        }
        return user;
    }

    public ResponseEntity<Map<String, Object>> forgotPassword(String usernameOrEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserModel user = getUserByUsernameOrEmail(usernameOrEmail);
        if (!user.isEmailVerified()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Email is not verified. Please verify your email before resetting password"));
        }
        Set<MfaType> methods = user.getMfaMethods();
        methods.add(EMAIL_MFA);
        return ResponseEntity.ok(Map.of("message", "Please select a method to receive for password reset", "methods", methods));
    }

    public Map<String, String> forgotPasswordMethodSelection(String usernameOrEmail, String method) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        validateTypeExistence(method);
        MfaType methodType = MfaType.valueOf(method.toUpperCase());
        UserModel user = getUserByUsernameOrEmail(usernameOrEmail);
        Set<MfaType> methods = user.getMfaMethods();
        methods.add(EMAIL_MFA);
        if (!methods.contains(methodType)) {
            throw new SimpleBadRequestException("Mfa method: '" + method + "' is not enabled for user");
        }
        switch (methodType) {
            case EMAIL_MFA -> {
                mailService.sendEmailAsync(user.getEmail(), "Otp for resetting password", generateOtpForForgotPassword(user), OTP);
                return Map.of("Message", "Otp sent to your email. Please check your email to reset your password");
            }
            case AUTHENTICATOR_APP_MFA -> {
                return Map.of("message", "Please proceed to verify Totp");
            }
        }
        throw new SimpleBadRequestException("Unsupported Mfa type: " + method + ". Supported types: " + MFA_METHODS);
    }

    private String generateOtpForForgotPassword(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        String otp = generateOtp();
        redisService.save(getEncryptedForgotPasswordOtpKey(user), genericAesRandomEncryptorDecryptor.encrypt(otp));
        return otp;
    }

    private String getEncryptedForgotPasswordOtpKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return genericAesStaticEncryptorDecryptor.encrypt(FORGOT_PASSWORD_OTP_PREFIX + user.getId());
    }

    public ResponseEntity<Map<String, Object>> resetPassword(ResetPwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        validateTypeExistence(dto.getMethod());
        Set<String> invalidInputs = validateInputs(dto);
        if (!invalidInputs.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        }
        MfaType methodType = MfaType.valueOf(dto.getMethod().toUpperCase());
        UserModel user = getUserByUsernameOrEmail(dto.getUsernameOrEmail());
        Set<MfaType> methods = user.getMfaMethods();
        methods.add(EMAIL_MFA);
        if (!methods.contains(methodType)) {
            throw new SimpleBadRequestException("Mfa method: '" + dto.getMethod() + "' is not enabled for user");
        }
        switch (methodType) {
            case EMAIL_MFA -> {
                return ResponseEntity.ok(verifyEmailOtpToResetPassword(user, dto));
            }
            case AUTHENTICATOR_APP_MFA -> {
                return ResponseEntity.ok(verifyAuthenticatorAppTotpToResetPassword(user, dto));
            }
        }
        throw new SimpleBadRequestException("Unsupported Mfa type: " + dto.getMethod() + ". Supported types: " + MFA_METHODS);
    }

    private Map<String, Object> verifyEmailOtpToResetPassword(UserModel user, ResetPwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        String encryptedForgotPasswordOtpKey = getEncryptedForgotPasswordOtpKey(user);
        Object encryptedOtp = redisService.get(encryptedForgotPasswordOtpKey);
        if (encryptedOtp != null) {
            if (genericAesRandomEncryptorDecryptor.decrypt((String) encryptedOtp, String.class).equals(dto.getOtpTotp())) {
                try {
                    redisService.delete(encryptedForgotPasswordOtpKey);
                } catch (Exception ignored) {
                }
                selfChangePassword(user, dto.getPassword());
                emailConfirmationOnPasswordReset(user);
                return Map.of("message", "Password reset successful");
            }
            throw new SimpleBadRequestException("Invalid Otp");
        }
        throw new SimpleBadRequestException("Invalid Otp");
    }

    private void selfChangePassword(UserModel user, String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        user.recordPasswordChange(passwordEncoder.encode(password));
        user.recordUpdation(genericAesRandomEncryptorDecryptor.encrypt("SELF"));
        userRepo.save(user);
    }

    private void emailConfirmationOnPasswordReset(UserModel user) {
        if (unleash.isEnabled(EMAIL_CONFIRMATION_ON_PASSWORD_RESET.name())) {
            mailService.sendEmailAsync(user.getEmail(), "Password reset confirmation", "", PASSWORD_RESET_CONFIRMATION);
        }
    }

    private Map<String, Object> verifyAuthenticatorAppTotpToResetPassword(UserModel user, ResetPwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (!verifyTotp(genericAesRandomEncryptorDecryptor.decrypt(user.getAuthAppSecret(), String.class), dto.getOtpTotp())) {
            throw new SimpleBadRequestException("Invalid Totp");
        }
        selfChangePassword(user, dto.getPassword());
        emailConfirmationOnPasswordReset(user);
        return Map.of("message", "Password reset successful");
    }

    public ResponseEntity<Map<String, Object>> changePassword(ChangePwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        Set<String> invalidInputs = validateInputsPasswordAndConfirmPassword(dto);
        try {
            validatePassword(dto.getOldPassword());
        } catch (SimpleBadRequestException ex) {
            invalidInputs.add("Invalid old password");
        }
        if (!invalidInputs.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        }
        UserModel user = getCurrentAuthenticatedUser();
        if (unleash.isEnabled(MFA.name())) {
            if (unleashUtility.shouldDoMfa(user)) {
                return ResponseEntity.ok(Map.of("message", "Please select a method to password change", "methods", user.getMfaMethods()));
            }
            if (unleash.isEnabled(FORCE_MFA.name())) {
                return ResponseEntity.ok(Map.of("message", "Please select a method to password change", "methods", Set.of(EMAIL_MFA)));
            }
        }
        user = userRepo.findById(user.getId()).orElseThrow(() -> new SimpleBadRequestException("Invalid user"));
        if (!passwordEncoder.matches(dto.getOldPassword(), user.getPassword())) {
            throw new SimpleBadRequestException("Invalid old password");
        }
        selfChangePassword(user, dto.getPassword());
        emailConfirmationOnSelfPasswordChange(user);
        return ResponseEntity.ok(Map.of("message", "Password changed successfully"));
    }

    private void emailConfirmationOnSelfPasswordChange(UserModel user) {
        if (unleash.isEnabled(EMAIL_CONFIRMATION_ON_SELF_PASSWORD_CHANGE.name())) {
            mailService.sendEmailAsync(user.getEmail(), "Password change confirmation", "", SELF_PASSWORD_CHANGE_CONFIRMATION);
        }
    }

    public Map<String, String> changePasswordMethodSelection(String method) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        validateTypeExistence(method);
        unleashUtility.isMfaEnabledGlobally();
        UserModel user = getCurrentAuthenticatedUser();
        MfaType methodType = MfaType.valueOf(method.toUpperCase());
        switch (methodType) {
            case EMAIL_MFA -> {
                if (user.getMfaMethods().isEmpty()) {
                    if (!unleash.isEnabled(FORCE_MFA.name())) {
                        throw new SimpleBadRequestException("Email Mfa is not enabled");
                    }
                    return sendEmailOtpToChangePassword(user);
                } else if (user.hasMfaMethod(EMAIL_MFA)) {
                    if (!unleash.isEnabled(MFA_EMAIL.name())) {
                        throw new ServiceUnavailableException("Email Mfa is disabled globally");
                    }
                    return sendEmailOtpToChangePassword(user);
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
        throw new SimpleBadRequestException("Unsupported Mfa type: " + method + ". Supported types: " + MFA_METHODS);
    }

    private Map<String, String> sendEmailOtpToChangePassword(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        mailService.sendEmailAsync(user.getEmail(), "Otp for password change", generateOtpForPasswordChange(user), OTP);
        return Map.of("message", "Otp sent to your registered email address. Please check your email to continue");
    }

    private String generateOtpForPasswordChange(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        String otp = generateOtp();
        redisService.save(getEncryptedPasswordChangeOtpKey(user), genericAesRandomEncryptorDecryptor.encrypt(otp));
        return otp;
    }

    private String getEncryptedPasswordChangeOtpKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return genericAesStaticEncryptorDecryptor.encrypt(EMAIL_OTP_FOR_PASSWORD_CHANGE_PREFIX + user.getId());
    }

    public ResponseEntity<Map<String, Object>> verifyChangePassword(ChangePwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        validateTypeExistence(dto.getMethod());
        Set<String> invalidInputs = validateInputsPasswordAndConfirmPassword(dto);
        try {
            validateOtp(dto.getOtpTotp(), "Otp/Totp");
        } catch (SimpleBadRequestException ex) {
            invalidInputs.add("Invalid Otp/Totp");
        }
        if (!invalidInputs.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        }
        unleashUtility.isMfaEnabledGlobally();
        UserModel user = getCurrentAuthenticatedUser();
        MfaType methodType = MfaType.valueOf(dto.getMethod().toUpperCase());
        switch (methodType) {
            case EMAIL_MFA -> {
                if (user.getMfaMethods().isEmpty()) {
                    if (!unleash.isEnabled(FORCE_MFA.name())) {
                        throw new SimpleBadRequestException("Email Mfa is not enabled");
                    }
                    return ResponseEntity.ok(verifyEmailOtpToChangePassword(user, dto));
                } else if (user.hasMfaMethod(EMAIL_MFA)) {
                    if (!unleash.isEnabled(MFA_EMAIL.name())) {
                        throw new ServiceUnavailableException("Email Mfa is disabled globally");
                    }
                    return ResponseEntity.ok(verifyEmailOtpToChangePassword(user, dto));
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
                return ResponseEntity.ok(verifyAuthenticatorAppTotpToChangePassword(user, dto));
            }
        }
        throw new SimpleBadRequestException("Unsupported Mfa type: " + dto.getMethod() + ". Supported types: " + MFA_METHODS);
    }

    private Map<String, Object> verifyEmailOtpToChangePassword(UserModel user, ChangePwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        String encryptedPasswordChangeOtpKey = getEncryptedPasswordChangeOtpKey(user);
        Object encryptedOtp = redisService.get(encryptedPasswordChangeOtpKey);
        if (encryptedOtp != null) {
            if (genericAesRandomEncryptorDecryptor.decrypt((String) encryptedOtp, String.class).equals(dto.getOtpTotp())) {
                try {
                    redisService.delete(encryptedPasswordChangeOtpKey);
                } catch (Exception ignored) {
                }
                user = userRepo.findById(user.getId()).orElseThrow(() -> new SimpleBadRequestException("Invalid user"));
                selfChangePassword(user, dto.getPassword());
                emailConfirmationOnSelfPasswordChange(user);
                return Map.of("message", "Password change successful");
            }
            throw new SimpleBadRequestException("Invalid Otp");
        }
        throw new SimpleBadRequestException("Invalid Otp");
    }

    private Map<String, Object> verifyAuthenticatorAppTotpToChangePassword(UserModel user, ChangePwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        user = userRepo.findById(user.getId()).orElseThrow(() -> new SimpleBadRequestException("Invalid user"));
        if (!verifyTotp(genericAesRandomEncryptorDecryptor.decrypt(user.getAuthAppSecret(), String.class), dto.getOtpTotp())) {
            throw new SimpleBadRequestException("Invalid Totp");
        }
        selfChangePassword(user, dto.getPassword());
        emailConfirmationOnSelfPasswordChange(user);
        return Map.of("message", "Password change successful");
    }

    public Map<String, String> emailChangeRequest(String newEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(EMAIL_CHANGE_ENABLED.name())) {
            validateEmail(newEmail);
            UserModel user = getCurrentAuthenticatedUser();
            String encryptedNewEmail = genericAesStaticEncryptorDecryptor.encrypt(newEmail);
            if (user.getEmail().equals(encryptedNewEmail)) {
                throw new SimpleBadRequestException("New email cannot be same as current email");
            }
            if (userRepo.existsByEmail(encryptedNewEmail)) {
                throw new SimpleBadRequestException("Email: '" + newEmail + "' is already taken");
            }
            String normalizedNewEmail = normalizeEmail(newEmail);
            String encryptedNormalizedNewEmail = genericAesStaticEncryptorDecryptor.encrypt(normalizedNewEmail);
            if (!user.getRealEmail().equals(normalizedNewEmail)) {
                if (userRepo.existsByRealEmail(encryptedNormalizedNewEmail)) {
                    throw new SimpleBadRequestException("Alias version of email: '" + newEmail + "' is already taken");
                }
            }
            storeNewEmailForEmailChange(user, newEmail);
            mailService.sendEmailAsync(newEmail, "Otp for email change in new email", generateOtpForEmailChangeForNewEmail(user), OTP);
            mailService.sendEmailAsync(user.getEmail(), "Otp for email change in old email", generateOtpForEmailChangeForOldEmail(user), OTP);
            return Map.of("message", "Otp's sent to your new & old email. Please check your emails to verify your email change");
        }
        throw new ServiceUnavailableException("Email change is currently disabled. Please try again later");
    }

    private void storeNewEmailForEmailChange(UserModel user, String newEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        redisService.save(getEncryptedNewEmailKey(user), genericAesRandomEncryptorDecryptor.encrypt(newEmail));
    }

    private String getEncryptedNewEmailKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return genericAesStaticEncryptorDecryptor.encrypt(EMAIL_STORE_PREFIX + user.getId());
    }

    private String generateOtpForEmailChangeForNewEmail(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        String otp = generateOtp();
        redisService.save(getEncryptedNewEmailChangeOtpKey(user), genericAesRandomEncryptorDecryptor.encrypt(otp));
        return otp;
    }

    private String getEncryptedNewEmailChangeOtpKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return genericAesStaticEncryptorDecryptor.encrypt(EMAIL_CHANGE_OTP_FOR_NEW_EMAIL_PREFIX + user.getId());
    }

    private String generateOtpForEmailChangeForOldEmail(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        String otp = generateOtp();
        redisService.save(getEncryptedOldEmailChangeOtpKey(user), genericAesRandomEncryptorDecryptor.encrypt(otp));
        return otp;
    }

    private String getEncryptedOldEmailChangeOtpKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return genericAesStaticEncryptorDecryptor.encrypt(EMAIL_CHANGE_OTP_FOR_OLD_EMAIL_PREFIX + user.getId());
    }

    public Map<String, Object> verifyEmailChange(String newEmailOtp, String oldEmailOtp, String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(EMAIL_CHANGE_ENABLED.name())) {
            try {
                validateOtp(newEmailOtp, "New email Otp");
                validateOtp(oldEmailOtp, "Old email Otp");
            } catch (SimpleBadRequestException ex) {
                throw new SimpleBadRequestException("Invalid Otp's");
            }
            UserModel user = getCurrentAuthenticatedUser();
            String encryptedNewEmailChangeOtpKey = getEncryptedNewEmailChangeOtpKey(user);
            Object encryptedNewEmailOtp = redisService.get(encryptedNewEmailChangeOtpKey);
            if (encryptedNewEmailOtp == null) {
                throw new SimpleBadRequestException("Invalid Otp's");
            }
            if (!genericAesRandomEncryptorDecryptor.decrypt((String) encryptedNewEmailOtp, String.class).equals(newEmailOtp)) {
                throw new SimpleBadRequestException("Invalid Otp's");
            }
            String encryptedOldEmailChangeOtpKey = getEncryptedOldEmailChangeOtpKey(user);
            Object encryptedOldEmailOtp = redisService.get(encryptedOldEmailChangeOtpKey);
            if (encryptedOldEmailOtp == null) {
                throw new SimpleBadRequestException("Invalid Otp's");
            }
            if (!genericAesRandomEncryptorDecryptor.decrypt((String) encryptedOldEmailOtp, String.class).equals(oldEmailOtp)) {
                throw new SimpleBadRequestException("Invalid Otp's");
            }
            String encryptedNewEmailKey = getEncryptedNewEmailKey(user);
            Object encryptedStoredNewEmail = redisService.get(encryptedNewEmailKey);
            if (encryptedStoredNewEmail == null) {
                throw new SimpleBadRequestException("Invalid Otp's");
            }
            String newEmail = genericAesRandomEncryptorDecryptor.decrypt((String) encryptedStoredNewEmail, String.class);
            String encryptedNewEmail = genericAesStaticEncryptorDecryptor.encrypt(newEmail);
            if (user.getEmail().equals(encryptedNewEmail)) {
                throw new SimpleBadRequestException("New email cannot be same as current email");
            }
            if (userRepo.existsByEmail(encryptedNewEmail)) {
                throw new SimpleBadRequestException("Email: '" + newEmail + "' is already taken");
            }
            String normalizedNewEmail = normalizeEmail(newEmail);
            String encryptedNormalizedNewEmail = genericAesStaticEncryptorDecryptor.encrypt(normalizedNewEmail);
            if (!user.getRealEmail().equals(normalizedNewEmail)) {
                if (userRepo.existsByRealEmail(encryptedNormalizedNewEmail)) {
                    throw new SimpleBadRequestException("Alias version of email: '" + newEmail + "' is already taken");
                }
            }
            user = userRepo.findById(user.getId()).orElseThrow(() -> new SimpleBadRequestException("Invalid user"));
            if (!passwordEncoder.matches(password, user.getPassword())) {
                throw new SimpleBadRequestException("Invalid password");
            }
            String oldEmail = genericAesStaticEncryptorDecryptor.decrypt(user.getEmail(), String.class);
            user.setEmail(encryptedNewEmail);
            user.setRealEmail(encryptedNormalizedNewEmail);
            accessTokenUtility.revokeTokens(Set.of(user));
            try {
                redisService.deleteAll(Set.of(encryptedNewEmailChangeOtpKey, encryptedOldEmailChangeOtpKey, encryptedNewEmailKey));
            } catch (Exception ignored) {
            }
            if (unleash.isEnabled(EMAIL_CONFIRMATION_ON_SELF_EMAIL_CHANGE.name())) {
                mailService.sendEmailAsync(oldEmail, "Email change confirmation on old email", "", SELF_EMAIL_CHANGE_CONFIRMATION);
            }
            return Map.of(
                    "message", "Email change successful. Please login again to continue",
                    "user", mapperUtility.toUserSummaryDto(userRepo.save(user))
            );
        }
        throw new ServiceUnavailableException("Email change is currently disabled. Please try again later");
    }

    public ResponseEntity<Map<String, Object>> deleteAccount(String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(ACCOUNT_DELETION_ALLOWED.name())) {
            try {
                validatePassword(password);
            } catch (SimpleBadRequestException ex) {
                throw new SimpleBadRequestException("Invalid password");
            }
            UserModel user = getCurrentAuthenticatedUser();
            if (unleash.isEnabled(MFA.name())) {
                if (unleashUtility.shouldDoMfa(user)) {
                    return ResponseEntity.ok(Map.of(
                            "message", "Please select a method for account deletion",
                            "methods", user.getMfaMethods())
                    );
                }
                if (unleash.isEnabled(FORCE_MFA.name())) {
                    return ResponseEntity.ok(Map.of(
                            "message", "Please select a method for account deletion",
                            "methods", Set.of(EMAIL_MFA))
                    );
                }
            }
            user = userRepo.findById(user.getId()).orElseThrow(() -> new SimpleBadRequestException("Invalid user"));
            if (!passwordEncoder.matches(password, user.getPassword())) {
                throw new SimpleBadRequestException("Invalid old password");
            }
            selfDeleteAccount(user);
            return ResponseEntity.ok(Map.of("message", "Account deleted successfully"));
        }
        throw new ServiceUnavailableException("Account deletion is currently disabled. Please try again later");
    }

    private void selfDeleteAccount(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        accessTokenUtility.revokeTokens(Set.of(user));
        user.recordAccountDeletion(true, genericAesRandomEncryptorDecryptor.encrypt("SELF"));
        userRepo.save(user);
        if (unleash.isEnabled(EMAIL_CONFIRMATION_ON_SELF_ACCOUNT_DELETION.name())) {
            mailService.sendEmailAsync(user.getEmail(), "Account deletion confirmation", "", ACCOUNT_DELETION_CONFIRMATION);
        }
    }

    public Map<String, String> deleteAccountMethodSelection(String method) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(ACCOUNT_DELETION_ALLOWED.name())) {
            validateTypeExistence(method);
            unleashUtility.isMfaEnabledGlobally();
            UserModel user = getCurrentAuthenticatedUser();
            MfaType methodType = MfaType.valueOf(method.toUpperCase());
            switch (methodType) {
                case EMAIL_MFA -> {
                    if (user.getMfaMethods().isEmpty()) {
                        if (!unleash.isEnabled(FORCE_MFA.name())) {
                            throw new SimpleBadRequestException("Email Mfa is not enabled");
                        }
                        return sendEmailOtpToDeleteAccount(user);
                    } else if (user.hasMfaMethod(EMAIL_MFA)) {
                        if (!unleash.isEnabled(MFA_EMAIL.name())) {
                            throw new ServiceUnavailableException("Email Mfa is disabled globally");
                        }
                        return sendEmailOtpToDeleteAccount(user);
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
            throw new SimpleBadRequestException("Unsupported Mfa type: " + method + ". Supported types: " + MFA_METHODS);
        }
        throw new ServiceUnavailableException("Account deletion is currently disabled. Please try again later");
    }

    private Map<String, String> sendEmailOtpToDeleteAccount(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        mailService.sendEmailAsync(user.getEmail(), "Otp for account deletion", generateEmailOtpForAccountDeletion(user), OTP);
        return Map.of("message", "Otp sent to your registered email address. Please check your email to continue");
    }

    private String generateEmailOtpForAccountDeletion(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        String otp = generateOtp();
        redisService.save(getEncryptedEmailOtpToDeleteAccountKey(user), genericAesRandomEncryptorDecryptor.encrypt(otp));
        return otp;
    }

    private String getEncryptedEmailOtpToDeleteAccountKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return genericAesStaticEncryptorDecryptor.encrypt(EMAIL_OTP_TO_DELETE_ACCOUNT_PREFIX + user.getId());
    }

    public Map<String, String> verifyDeleteAccount(String otpTotp, String method) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(ACCOUNT_DELETION_ALLOWED.name())) {
            validateTypeExistence(method);
            try {
                validateOtp(otpTotp, "Otp/Totp");
            } catch (SimpleBadRequestException ex) {
                throw new SimpleBadRequestException("Invalid Otp/Totp");
            }
            unleashUtility.isMfaEnabledGlobally();
            UserModel user = getCurrentAuthenticatedUser();
            MfaType methodType = MfaType.valueOf(method.toUpperCase());
            switch (methodType) {
                case EMAIL_MFA -> {
                    if (user.getMfaMethods().isEmpty()) {
                        if (!unleash.isEnabled(FORCE_MFA.name())) {
                            throw new SimpleBadRequestException("Email Mfa is not enabled");
                        }
                        return verifyEmailOtpToDeleteAccount(otpTotp, user);
                    } else if (user.hasMfaMethod(EMAIL_MFA)) {
                        if (!unleash.isEnabled(MFA_EMAIL.name())) {
                            throw new ServiceUnavailableException("Email Mfa is disabled globally");
                        }
                        return verifyEmailOtpToDeleteAccount(otpTotp, user);
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
                    return verifyAuthenticatorAppTOTPToDeleteAccount(otpTotp, user);
                }
            }
            throw new SimpleBadRequestException("Unsupported Mfa type: " + method + ". Supported types: " + MFA_METHODS);
        }
        throw new ServiceUnavailableException("Account deletion is currently disabled. Please try again later");
    }

    private Map<String, String> verifyEmailOtpToDeleteAccount(String otp, UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        String encryptedEmailOtpToDeleteAccountKey = getEncryptedEmailOtpToDeleteAccountKey(user);
        Object encryptedOtp = redisService.get(encryptedEmailOtpToDeleteAccountKey);
        if (encryptedOtp != null) {
            if (genericAesRandomEncryptorDecryptor.decrypt((String) encryptedOtp, String.class).equals(otp)) {
                try {
                    redisService.delete(encryptedEmailOtpToDeleteAccountKey);
                } catch (Exception ignored) {
                }
                user = userRepo.findById(user.getId()).orElseThrow(() -> new SimpleBadRequestException("Invalid user"));
                selfDeleteAccount(user);
                return Map.of("message", "Account deleted successfully");
            }
            throw new SimpleBadRequestException("Invalid Otp");
        }
        throw new SimpleBadRequestException("Invalid Otp");
    }

    private Map<String, String> verifyAuthenticatorAppTOTPToDeleteAccount(String totp, UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        user = userRepo.findById(user.getId()).orElseThrow(() -> new SimpleBadRequestException("Invalid user"));
        if (!verifyTotp(genericAesRandomEncryptorDecryptor.decrypt(user.getAuthAppSecret(), String.class), totp)) {
            throw new SimpleBadRequestException("Invalid Totp");
        }
        selfDeleteAccount(user);
        return Map.of("message", "Account deleted successfully");
    }

    public ResponseEntity<Map<String, Object>> updateDetails(SelfUpdationDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserModel user = userRepo.findById(getCurrentAuthenticatedUser().getId()).orElseThrow(() -> new SimpleBadRequestException("Invalid user"));
        SelfUpdationResultDto selfUpdationResult = validateAndSet(user, dto);
        if (!selfUpdationResult.getInvalidInputs().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("invalid_inputs", selfUpdationResult.getInvalidInputs()));
        }
        if (selfUpdationResult.isModified()) {
            user.recordUpdation(genericAesRandomEncryptorDecryptor.encrypt("SELF"));
            if (unleash.isEnabled(EMAIL_CONFIRMATION_ON_SELF_UPDATE_DETAILS.name())) {
                mailService.sendEmailAsync(genericAesStaticEncryptorDecryptor.decrypt(user.getEmail(), String.class), "Account details updated confirmation", "", SELF_UPDATE_DETAILS_CONFIRMATION);
            }
            Map<String, Object> response = new HashMap<>();
            if (selfUpdationResult.isShouldRemoveTokens()) {
                accessTokenUtility.revokeTokens(Set.of(user));
                response.put("message", "User details updated successfully. Please login again to continue");
            } else {
                response.put("message", "User details updated successfully");
            }
            response.put("user", mapperUtility.toUserSummaryDto(userRepo.save(user)));
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.ok(Map.of("message", "No details were updated"));
    }

    private SelfUpdationResultDto validateAndSet(UserModel user, SelfUpdationDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var selfUpdationResult = new SelfUpdationResultDto(false, false, new HashSet<>());
        try {
            validatePassword(dto.getOldPassword());
            if (!passwordEncoder.matches(dto.getOldPassword(), user.getPassword())) {
                selfUpdationResult.getInvalidInputs().add("Invalid old password");
            }
        } catch (SimpleBadRequestException ex) {
            selfUpdationResult.getInvalidInputs().add("Invalid old password");
        }
        if (dto.getFirstName() != null && !dto.getFirstName().equals(user.getFirstName())) {
            try {
                validateFirstName(dto.getFirstName());
                user.setFirstName(dto.getFirstName());
                selfUpdationResult.setModified(true);
            } catch (SimpleBadRequestException ex) {
                selfUpdationResult.getInvalidInputs().add(ex.getMessage());
            }
        }
        if (dto.getMiddleName() != null && !dto.getMiddleName().equals(user.getMiddleName())) {
            try {
                validateMiddleName(dto.getMiddleName());
                user.setMiddleName(dto.getMiddleName());
                selfUpdationResult.setModified(true);
            } catch (SimpleBadRequestException ex) {
                selfUpdationResult.getInvalidInputs().add(ex.getMessage());
            }
        }
        if (dto.getLastName() != null && !dto.getLastName().equals(user.getLastName())) {
            try {
                validateLastName(dto.getLastName());
                user.setLastName(dto.getLastName());
                selfUpdationResult.setModified(true);
            } catch (SimpleBadRequestException ex) {
                selfUpdationResult.getInvalidInputs().add(ex.getMessage());
            }
        }
        if (dto.getUsername() != null && !dto.getUsername().equals(genericAesStaticEncryptorDecryptor.decrypt(user.getUsername(), String.class))) {
            try {
                validateUsername(dto.getUsername());
                String encryptedUsername = genericAesStaticEncryptorDecryptor.encrypt(dto.getUsername());
                if (userRepo.existsByUsername(encryptedUsername)) {
                    selfUpdationResult.getInvalidInputs().add("Username already taken");
                } else {
                    user.setUsername(encryptedUsername);
                    selfUpdationResult.setModified(true);
                    selfUpdationResult.setShouldRemoveTokens(true);
                }
            } catch (SimpleBadRequestException ex) {
                selfUpdationResult.getInvalidInputs().add(ex.getMessage());
            }
        }
        return selfUpdationResult;
    }
}
