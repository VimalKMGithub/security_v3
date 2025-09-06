package org.vimal.security.v3.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.vimal.security.v3.models.UserModel;

import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UsersUpdationWithNewDetailsResultDto {
    private Set<UserModel> updatedUsers;
    private Set<UUID> idsOfUsersWeHaveToRemoveTokens;
}
