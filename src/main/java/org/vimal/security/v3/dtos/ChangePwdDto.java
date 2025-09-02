package org.vimal.security.v3.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ChangePwdDto extends ResetPwdDto {
    private String oldPassword;
}
