package org.vimal.security.v3.dtos;

import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
public class UserCreationDto extends RegistrationDto {
    public Set<String> roles;
    public boolean emailVerified;
    public boolean accountLocked;
    public boolean accountEnabled;
    public boolean accountDeleted;
}
