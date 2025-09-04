package org.vimal.security.v3.dtos;

import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
public class UserCreationDto extends RegistrationDto {
    private Set<String> roles;
    private boolean emailVerified;
    private boolean accountLocked;
    private boolean accountEnabled;
    private boolean accountDeleted;
}
