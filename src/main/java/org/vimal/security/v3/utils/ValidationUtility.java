package org.vimal.security.v3.utils;

import org.vimal.security.v3.dtos.RegistrationDto;
import org.vimal.security.v3.dtos.ResetPwdDto;
import org.vimal.security.v3.exceptions.SimpleBadRequestException;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

public final class ValidationUtility {
    private ValidationUtility() {
    }

    private static final int DEFAULT_OTP_LENGTH = 6;
    private static final Pattern UUID_PATTERN = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$");
    private static final Pattern NUMBER_ONLY_PATTERN = Pattern.compile("^[0-9]+$");
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]).{8,255}$");
    private static final Pattern NAME_PATTERN = Pattern.compile("^[\\p{L} .'-]+$");
    public static final Pattern EMAIL_PATTERN = Pattern.compile("^(?=.{1,64}@)[\\p{L}0-9]+([._+-][\\p{L}0-9]+)*@([\\p{L}0-9]+(-[\\p{L}0-9]+)*\\.)+\\p{L}{2,190}$");
    public static final Pattern USERNAME_PATTERN = Pattern.compile("^[\\p{L}0-9_-]{3,100}$");
    public static final Pattern ROLE_AND_PERMISSION_NAME_PATTERN = Pattern.compile("^[\\p{L}0-9_]+$");

    public static void validateStringIsNonNullAndNotBlank(String value,
                                                          String fieldName) {
        if (value == null) {
            throw new SimpleBadRequestException(fieldName + " cannot be null");
        }
        if (value.isBlank()) {
            throw new SimpleBadRequestException(fieldName + " cannot be blank");
        }
    }

    public static void validatePassword(String password) {
        validateStringIsNonNullAndNotBlank(
                password,
                "Password"
        );
        if (password.length() < 8 ||
                password.length() > 255) {
            throw new SimpleBadRequestException("Password must be between 8 and 255 characters long");
        }
        if (!PASSWORD_PATTERN.matcher(password)
                .matches()) {
            throw new SimpleBadRequestException("Password: '" + password + "' is invalid as it must contain at least one digit, one lowercase letter, one uppercase letter, and one special character");
        }
    }

    public static void validateUuid(String uuid,
                                    String fieldName) {
        validateStringIsNonNullAndNotBlank(
                uuid,
                fieldName
        );
        if (!UUID_PATTERN.matcher(uuid)
                .matches()) {
            throw new SimpleBadRequestException(fieldName + ": '" + uuid + "' is of invalid format");
        }
    }

    public static void validateOtp(String otp,
                                   String fieldName) {
        validateOtp(
                otp,
                fieldName,
                DEFAULT_OTP_LENGTH
        );
    }

    private static void validateOtp(String otp,
                                    String fieldName,
                                    int length) {
        validateStringIsNonNullAndNotBlank(
                otp,
                fieldName
        );
        if (otp.length() != length) {
            throw new SimpleBadRequestException(fieldName + " must be exactly " + length + " characters long");
        }
        if (!NUMBER_ONLY_PATTERN.matcher(otp)
                .matches()) {
            throw new SimpleBadRequestException(fieldName + "must contain numbers only");
        }
    }

    public static void validateUsername(String username) {
        validateStringIsNonNullAndNotBlank(
                username,
                "Username"
        );
        if (username.length() < 3 ||
                username.length() > 100) {
            throw new SimpleBadRequestException("Username must be between 3 and 100 characters long");
        }
        if (!USERNAME_PATTERN.matcher(username)
                .matches()) {
            throw new SimpleBadRequestException("Username: '" + username + "' is invalid as it can only contain letters, digits, underscores, and hyphens");
        }
    }

    public static void validateEmail(String email) {
        validateStringIsNonNullAndNotBlank(
                email,
                "Email"
        );
        if (email.length() > 320) {
            throw new SimpleBadRequestException("Email must be at most 320 characters long");
        }
        if (!EMAIL_PATTERN.matcher(email)
                .matches()) {
            throw new SimpleBadRequestException("Email: '" + email + "' is of invalid format");
        }
    }

    public static void validateRoleNameOrPermissionName(String name,
                                                        String fieldName) {
        validateStringIsNonNullAndNotBlank(
                name,
                fieldName
        );
        if (name.length() > 100) {
            throw new SimpleBadRequestException(fieldName + " must be at most 100 characters long");
        }
        if (!ROLE_AND_PERMISSION_NAME_PATTERN.matcher(name)
                .matches()) {
            throw new SimpleBadRequestException(fieldName + ": '" + name + "' is invalid as it can only contain letters, digits, and underscores");
        }
    }

    public static void validateFirstName(String firstName) {
        validateStringIsNonNullAndNotBlank(
                firstName,
                "First name"
        );
        if (firstName.length() > 50) {
            throw new SimpleBadRequestException("First name must be at most 50 characters long");
        }
        if (!NAME_PATTERN.matcher(firstName)
                .matches()) {
            throw new SimpleBadRequestException("First name: '" + firstName + "' is invalid as it can only contain letters, spaces, periods, apostrophes, and hyphens");
        }
    }

    public static void validateMiddleName(String middleName) {
        if (middleName == null) {
            return;
        }
        if (middleName.isBlank()) {
            throw new SimpleBadRequestException("Middle name cannot be blank if provided");
        }
        if (middleName.length() > 50) {
            throw new SimpleBadRequestException("Middle name must be at most 50 characters long");
        }
        if (!NAME_PATTERN.matcher(middleName)
                .matches()) {
            throw new SimpleBadRequestException("Middle name: '" + middleName + "' is invalid as it can only contain letters, spaces, periods, apostrophes, and hyphens");
        }
    }

    public static void validateLastName(String lastName) {
        if (lastName == null) {
            return;
        }
        if (lastName.isBlank()) {
            throw new SimpleBadRequestException("Last name cannot be blank if provided");
        }
        if (lastName.length() > 50) {
            throw new SimpleBadRequestException("Last name must be at most 50 characters long");
        }
        if (!NAME_PATTERN.matcher(lastName)
                .matches()) {
            throw new SimpleBadRequestException("Last name: '" + lastName + "' is invalid as it can only contain letters, spaces, periods, apostrophes, and hyphens");
        }
    }

    public static Set<String> validateInputs(RegistrationDto dto) {
        Set<String> validationErrors = new HashSet<>();
        try {
            validateUsername(dto.getUsername());
        } catch (SimpleBadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            validatePassword(dto.getPassword());
        } catch (SimpleBadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            validateEmail(dto.getEmail());
        } catch (SimpleBadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            validateFirstName(dto.getFirstName());
        } catch (SimpleBadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            validateMiddleName(dto.getMiddleName());
        } catch (SimpleBadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            validateLastName(dto.getLastName());
        } catch (SimpleBadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        return validationErrors;
    }

    public static Set<String> validateInputs(ResetPwdDto dto) {
        Set<String> validationErrors = validateInputsPasswordAndConfirmPassword(dto);
        try {
            validateStringIsNonNullAndNotBlank(
                    dto.getUsernameOrEmail(),
                    "Username/email"
            );
        } catch (SimpleBadRequestException ex) {
            validationErrors.add("Invalid username/email");
        }
        try {
            validateOtp(
                    dto.getOtpTotp(),
                    "Otp/Totp"
            );
        } catch (SimpleBadRequestException ex) {
            validationErrors.add("Invalid Otp/Totp");
        }
        return validationErrors;
    }

    public static Set<String> validateInputsPasswordAndConfirmPassword(ResetPwdDto dto) {
        Set<String> validationErrors = new HashSet<>();
        try {
            validatePassword(dto.getPassword());
            if (!dto.getPassword()
                    .equals(dto.getConfirmPassword())) {
                validationErrors.add("New password: '" + dto.getPassword() + "' and confirm password: '" + dto.getConfirmPassword() + "' do not match");
            }
        } catch (SimpleBadRequestException ex) {
            validationErrors.add("New " + ex.getMessage());
        }
        return validationErrors;
    }
}
