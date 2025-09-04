package org.vimal.security.v3.utils;

import org.vimal.security.v3.enums.MfaType;
import org.vimal.security.v3.exceptions.SimpleBadRequestException;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public final class MfaUtility {
    private MfaUtility() {
    }

    public static final Set<String> MFA_METHODS = buildMfaMethodsSet();

    private static Set<String> buildMfaMethodsSet() {
        Set<String> methods = new HashSet<>();
        for (MfaType type : MfaType.values()) {
            methods.add(type.name().toLowerCase());
        }
        return Collections.unmodifiableSet(methods);
    }

    public static void validateTypeExistence(String type) {
        if (!MFA_METHODS.contains(type.toLowerCase())) {
            throw new SimpleBadRequestException("Unsupported Mfa type: " + type + ". Supported types: " + MFA_METHODS);
        }
    }
}
