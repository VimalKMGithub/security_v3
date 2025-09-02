package org.vimal.security.v3.utils;

import org.vimal.security.v3.enums.MfaType;
import org.vimal.security.v3.exceptions.SimpleBadRequestException;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public final class MfaUtility {
    private MfaUtility() {
    }

    public static final Set<String> MFA_METHODS = Arrays.stream(MfaType.values()).map(e -> e.name().toLowerCase()).collect(Collectors.toSet());

    public static void validateTypeExistence(String type) {
        if (!MFA_METHODS.contains(type.toLowerCase())) {
            throw new SimpleBadRequestException("Unsupported Mfa type: " + type + ". Supported types: " + MFA_METHODS);
        }
    }
}
