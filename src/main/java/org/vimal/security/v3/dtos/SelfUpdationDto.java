package org.vimal.security.v3.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SelfUpdationDto {
    private String username;
    private String firstName;
    private String middleName;
    private String lastName;
    private String oldPassword;
}
