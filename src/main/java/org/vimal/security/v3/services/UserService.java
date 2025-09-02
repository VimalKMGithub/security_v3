package org.vimal.security.v3.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v3.dtos.RegistrationDto;
import org.vimal.security.v3.encryptordecryptors.GenericAesRandomEncryptorDecryptor;
import org.vimal.security.v3.encryptordecryptors.GenericAesStaticEncryptorDecryptor;
import org.vimal.security.v3.exceptions.ServiceUnavailableException;
import org.vimal.security.v3.repos.UserRepo;
import org.vimal.security.v3.utils.AccessTokenUtility;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import static org.vimal.security.v3.enums.FeatureFlags.REGISTRATION_ENABLED;

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
    private final GenericAesStaticEncryptorDecryptor genericAesStaticEncryptorDecryptor;
    private final GenericAesRandomEncryptorDecryptor genericAesRandomEncryptorDecryptor;

    public ResponseEntity<Map<String, Object>> register(RegistrationDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(REGISTRATION_ENABLED.name())) {
//            var invalidInputs = UserUtility.validateInputs(dto);
//            if (!invalidInputs.isEmpty()) {
//                return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
//            }
//            if (userRepo.existsByUsername(dto.getUsername())) {
//                throw new BadRequestException("Username: '" + dto.getUsername() + "' is already taken");
//            }
//            if (userRepo.existsByEmail(dto.getEmail())) {
//                throw new BadRequestException("Email: '" + dto.getEmail() + "' is already registered");
//            }
//            var sanitizedEmail = sanitizeEmail(dto.getEmail());
//            if (userRepo.existsByRealEmail(sanitizedEmail)) {
//                throw new BadRequestException("Alias version of email: '" + dto.getEmail() + "' is already registered");
//            }
//            var user = toUserModel(dto, sanitizedEmail);
//            var shouldVerifyRegisteredEmail = unleash.isEnabled(FeatureFlags.REGISTRATION_EMAIL_VERIFICATION.name());
//            user.setEmailVerified(!shouldVerifyRegisteredEmail);
//            if (shouldVerifyRegisteredEmail) {
//                mailService.sendEmailAsync(user.getEmail(), "Email verification link after registration", "https://godLevelSecurity.com/verifyEmailAfterRegistration?token=" + generateEmailVerificationToken(user), MailService.MailType.LINK);
//                return ResponseEntity.ok(Map.of("message", "Registration successful. Please check your email for verification link", "user", userRepo.save(user)));
//            }
//            return ResponseEntity.ok(Map.of("message", "Registration successful", "user", userRepo.save(user)));
        }
        throw new ServiceUnavailableException("Registration is currently disabled. Please try again later");
    }
}
