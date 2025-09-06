package org.vimal.security.v3.utils;

import org.springframework.security.core.Authentication;
import org.vimal.security.v3.exceptions.UnauthorizedException;
import org.vimal.security.v3.impls.UserDetailsImpl;
import org.vimal.security.v3.models.UserModel;

import static org.springframework.security.core.context.SecurityContextHolder.getContext;

public final class UserUtility {
    private UserUtility() {
    }

    public static UserModel getCurrentAuthenticatedUser() {
        return getCurrentAuthenticatedUserDetails().getUser();
    }

    public static UserDetailsImpl getCurrentAuthenticatedUserDetails() {
        return (UserDetailsImpl) getAuthenticationOfCurrentAuthenticatedUser().getPrincipal();
    }

    public static Authentication getAuthenticationOfCurrentAuthenticatedUser() {
        Authentication authentication = getContext().getAuthentication();
        if (authentication != null
                && authentication.isAuthenticated()
                && authentication.getPrincipal() instanceof UserDetailsImpl) {
            return authentication;
        }
        throw new UnauthorizedException("User not authenticated");
    }
}
