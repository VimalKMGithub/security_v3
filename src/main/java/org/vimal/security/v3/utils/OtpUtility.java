package org.vimal.security.v3.utils;

import org.vimal.security.v3.exceptions.SimpleBadRequestException;

import java.security.SecureRandom;

public final class OtpUtility {
    private OtpUtility() {
    }

    public static final SecureRandom SECURE_RANDOM = new SecureRandom();
    public static final String DIGITS = "0123456789";
    public static final int DEFAULT_OTP_LENGTH = 6;

    public static String generateOtp() {
        return generateOtp(DEFAULT_OTP_LENGTH);
    }

    private static String generateOtp(int length) {
        if (length < 1) {
            throw new SimpleBadRequestException("Otp length must be at least 1");
        }
        char[] otpChars = new char[length];
        for (int i = 0; i < length; i++) {
            otpChars[i] = DIGITS.charAt(SECURE_RANDOM.nextInt(DIGITS.length()));
        }
        return new String(otpChars);
    }
}
