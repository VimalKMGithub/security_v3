package org.vimal.security.v3.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.vimal.security.v3.models.RoleModel;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RolesUpdationWithNewDetailsResultDto {
    private Set<RoleModel> updatedRoles;
    private Set<String> roleNamesOfRolesWeHaveToRemoveFromUsers;
}
