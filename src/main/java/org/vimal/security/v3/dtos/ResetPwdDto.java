package org.vimal.security.v3.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResetPwdDto {
    private String usernameOrEmail;
    public String otpTotp;
    public String method;
    public String password;
    public String confirmPassword;
}
