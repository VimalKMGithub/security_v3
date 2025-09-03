package org.vimal.security.v3.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.vimal.security.v3.models.UserModel;

import java.util.Map;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ValidateInputsForDeleteUsersResultDto {
    private Map<String, Object> mapOfErrors;
    private Set<UserModel> usersToDelete;
}
