package org.vimal.security.v3.dtos;

import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.Set;

@Getter
@Setter
public class RoleSummaryDto {
    private String roleName;
    private String description;
    private String createdBy;
    private String updatedBy;
    private Set<String> permissions;
    private Instant createdAt;
    private Instant updatedAt;
    private boolean systemRole;
}
