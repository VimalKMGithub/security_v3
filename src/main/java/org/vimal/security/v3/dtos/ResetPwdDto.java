package org.vimal.security.v3.dtos;

import lombok.Getter;
import lombok.Setter;

import static org.vimal.security.v3.enums.MfaType.DEFAULT_MFA;

@Getter
@Setter
public class ResetPwdDto {
    private String usernameOrEmail;
    private String otpTotp;
    private String method = DEFAULT_MFA;
    private String password;
    private String confirmPassword;
}
