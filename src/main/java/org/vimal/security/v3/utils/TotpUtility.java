package org.vimal.security.v3.utils;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import org.apache.commons.codec.binary.Base32;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

public final class TotpUtility {
    private TotpUtility() {
    }

    private static final TimeBasedOneTimePasswordGenerator TOTP_GENERATOR = new TimeBasedOneTimePasswordGenerator();
    private static final Base32 BASE_32 = new Base32();
    private static final ThreadLocal<KeyGenerator> KEY_GENERATOR = ThreadLocal.withInitial(() -> {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(TOTP_GENERATOR.getAlgorithm());
            keyGen.init(160);
            return keyGen;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Totp algorithm not available", e);
        }
    });

    public static String generateBase32Secret() {
        return BASE_32.encodeToString(KEY_GENERATOR.get().generateKey().getEncoded()).replace("=", "");
    }

    public static String generateTotpUrl(String issuer, String accountName, String base32Secret) {
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", urlEncode(issuer), urlEncode(accountName), base32Secret, urlEncode(issuer));
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String generateTotp(String base32Secret) throws InvalidKeyException {
        return TOTP_GENERATOR.generateOneTimePasswordString(new SecretKeySpec(BASE_32.decode(base32Secret), TOTP_GENERATOR.getAlgorithm()), Instant.now());
    }

    public static boolean verifyTotp(String base32Secret, String userInputCode) throws InvalidKeyException {
        return generateTotp(base32Secret).equals(userInputCode);
    }
}
