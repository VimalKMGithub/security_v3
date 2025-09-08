package org.vimal.security.v3.utils;

import java.security.SecureRandom;

public final class OtpUtility {
    private OtpUtility() {
    }

    private static final ThreadLocal<SecureRandom> SECURE_RANDOM = ThreadLocal.withInitial(SecureRandom::new);
    public static final String DIGITS = "0123456789";
    public static final int DEFAULT_OTP_LENGTH = 6;

    public static String generateOtp() {
        return generateOtp(DEFAULT_OTP_LENGTH);
    }

    private static String generateOtp(int length) {
        if (length < 1) {
            throw new IllegalArgumentException("Otp length must be at least 1");
        }
        char[] otpChars = new char[length];
        for (int i = 0; i < length; i++) {
            otpChars[i] = DIGITS.charAt(SECURE_RANDOM.get()
                    .nextInt(DIGITS.length()));
        }
        return new String(otpChars);
    }
}
