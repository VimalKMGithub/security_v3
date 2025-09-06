package org.vimal.security.v3.utils;

import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.vimal.security.v3.exceptions.ServiceUnavailableException;
import org.vimal.security.v3.models.UserModel;

import static org.vimal.security.v3.enums.FeatureFlags.*;
import static org.vimal.security.v3.enums.MfaType.AUTHENTICATOR_APP_MFA;
import static org.vimal.security.v3.enums.MfaType.EMAIL_MFA;

@Component
@RequiredArgsConstructor
public class UnleashUtility {
    private final Unleash unleash;

    public boolean shouldDoMfa(UserModel user) {
        boolean doMfa = false;
        if (user.isMfaEnabled() &&
                !user.getMfaMethods().isEmpty()) {
            boolean unleashEmailMfa = unleash.isEnabled(MFA_EMAIL.name());
            boolean unleashAuthenticatorAppMfa = unleash.isEnabled(MFA_AUTHENTICATOR_APP.name());
            if (unleashEmailMfa &&
                    user.hasMfaMethod(EMAIL_MFA)) {
                doMfa = true;
            } else if (unleashAuthenticatorAppMfa &&
                    user.hasMfaMethod(AUTHENTICATOR_APP_MFA)) {
                doMfa = true;
            }
        }
        return doMfa;
    }

    public void isMfaEnabledGlobally() {
        if (!unleash.isEnabled(MFA.name())) {
            throw new ServiceUnavailableException("Mfa is disabled globally");
        }
    }
}
