package org.vimal.security.v3.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Set;

@Getter
@AllArgsConstructor
public class SystemUserDto {
    private String username;
    private String password;
    private String email;
    private String firstName;
    private Set<String> roles;
}
