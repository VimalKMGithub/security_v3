package org.vimal.security.v3.utils;

import org.vimal.security.v3.exceptions.SimpleBadRequestException;

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

    public static void validateStringIsNonNullAndNotBlank(String value, String fieldName) {
        if (value == null) {
            throw new SimpleBadRequestException(fieldName + " cannot be null");
        }
        if (value.isBlank()) {
            throw new SimpleBadRequestException(fieldName + " cannot be blank");
        }
    }

    public static void validatePassword(String password) {
        validateStringIsNonNullAndNotBlank(password, "Password");
        if (password.length() < 8 || password.length() > 255) {
            throw new SimpleBadRequestException("Password must be between 8 and 255 characters long");
        }
        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            throw new SimpleBadRequestException("Password: '" + password + "' is invalid as it must contain at least one digit, one lowercase letter, one uppercase letter, and one special character");
        }
    }
}
