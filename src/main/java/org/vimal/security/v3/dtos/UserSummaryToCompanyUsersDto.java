package org.vimal.security.v3.dtos;

import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
public class UserSummaryToCompanyUsersDto extends UserSummaryDto {
    private String realEmail;
    private boolean accountDeleted;
    private Instant accountDeletedAt;
    private String accountDeletedBy;
    private Instant accountRecoveredAt;
    private String accountRecoveredBy;
}
