package org.vimal.security.v3.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v3.dtos.RegistrationDto;
import org.vimal.security.v3.dtos.UserSummaryDto;
import org.vimal.security.v3.encryptordecryptors.GenericAesRandomEncryptorDecryptor;
import org.vimal.security.v3.encryptordecryptors.GenericAesStaticEncryptorDecryptor;
import org.vimal.security.v3.exceptions.ServiceUnavailableException;
import org.vimal.security.v3.exceptions.SimpleBadRequestException;
import org.vimal.security.v3.models.UserModel;
import org.vimal.security.v3.repos.UserRepo;
import org.vimal.security.v3.utils.AccessTokenUtility;
import org.vimal.security.v3.utils.MapperUtility;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.vimal.security.v3.enums.FeatureFlags.REGISTRATION_EMAIL_VERIFICATION;
import static org.vimal.security.v3.enums.FeatureFlags.REGISTRATION_ENABLED;
import static org.vimal.security.v3.enums.MailType.LINK;
import static org.vimal.security.v3.utils.EmailUtility.normalizeEmail;
import static org.vimal.security.v3.utils.UserUtility.getCurrentAuthenticatedUser;
import static org.vimal.security.v3.utils.ValidationUtility.validateInputs;
import static org.vimal.security.v3.utils.ValidationUtility.validateUuid;

@Service
@RequiredArgsConstructor
public class UserService {
    private static final String EMAIL_VERIFICATION_TOKEN_PREFIX = "SECURITY_V3_EMAIL_VERIFICATION_TOKEN:";
    private static final String EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX = "SECURITY_V3_EMAIL_VERIFICATION_TOKEN_MAPPING:";
    private static final String FORGOT_PASSWORD_OTP_PREFIX = "SECURITY_V3_FORGOT_PASSWORD_OTP:";
    private static final String EMAIL_CHANGE_OTP_PREFIX = "SECURITY_V3_EMAIL_CHANGE_OTP:";
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
}
