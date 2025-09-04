package org.vimal.security.v3.dtos;

import lombok.Getter;
import lombok.Setter;

import static org.vimal.security.v3.enums.MfaType.DEFAULT_MFA;

@Getter
@Setter
public class ResetPwdDto {
    private String usernameOrEmail;
    public String otpTotp;
    public String method = DEFAULT_MFA;
    public String password;
    public String confirmPassword;
}
