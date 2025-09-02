package org.vimal.security.v3.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegistrationDto {
    public String username;
    public String password;
    public String email;
    public String firstName;
    public String middleName;
    public String lastName;
}
