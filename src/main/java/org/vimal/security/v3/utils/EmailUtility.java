package org.vimal.security.v3.utils;

import java.util.Set;

public final class EmailUtility {
    private EmailUtility() {
    }

    private static final Set<String> REMOVE_DOTS = Set.of(
            "gmail.com",
            "googlemail.com"
    );
    private static final Set<String> REMOVE_ALIAS_PART = Set.of(
            "gmail.com",
            "googlemail.com",
            "live.com",
            "protonmail.com",
            "hotmail.com",
            "outlook.com"
    );

    public static String normalizeEmail(String email) {
        String lowerCasedEmail = email.trim()
                .toLowerCase();
        int atIndex = lowerCasedEmail.indexOf('@');
        String local = lowerCasedEmail.substring(0, atIndex);
        String domain = lowerCasedEmail.substring(atIndex + 1);
        if (REMOVE_DOTS.contains(domain)) {
            local = local.replace(
                    ".",
                    ""
            );
        }
        if (REMOVE_ALIAS_PART.contains(domain)) {
            int plusIndex = local.indexOf('+');
            if (plusIndex != -1) {
                local = local.substring(0, plusIndex);
            }
        }
        return local + "@" + domain;
    }
}
