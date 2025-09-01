package org.vimal.security.v3.exceptions;

import org.springframework.security.core.AuthenticationException;

public class CustomLockedException extends AuthenticationException {
    public CustomLockedException(String message) {
        super(message);
    }
}
