package org.vimal.security.v3.enums;

import static org.vimal.security.v3.enums.FeatureFlags.MFA_AUTHENTICATOR_APP;
import static org.vimal.security.v3.enums.FeatureFlags.MFA_EMAIL;

public enum MfaType {
    EMAIL_MFA,
    AUTHENTICATOR_APP_MFA;
    public static final String DEFAULT_MFA = "EMAIL_MFA";

    public FeatureFlags toFeatureFlag() {
        return switch (this) {
            case EMAIL_MFA -> MFA_EMAIL;
            case AUTHENTICATOR_APP_MFA -> MFA_AUTHENTICATOR_APP;
        };
    }
}
