package org.vimal.security.v3.utils;

import java.util.Set;

public final class ToggleUtility {
    private ToggleUtility() {
    }

    public static final String DEFAULT_TOGGLE = "disable";
    public static final Set<String> TOGGLE_TYPE = Set.of(
            "enable",
            "disable"
    );
}
