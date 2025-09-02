package org.vimal.security.v3.dtos;

import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
public class UserSummaryDto {
    public UUID id;
    public String firstName;
    public String middleName;
    public String lastName;
    public String username;
    public String email;
    public String createdBy;
    public String updatedBy;
    public Set<String> roles;
    public Set<String> mfaMethods;
    public Instant lastLoginAt;
    public Instant passwordChangedAt;
    public Instant createdAt;
    public Instant updatedAt;
    public Instant lastLockedAt;
    public boolean emailVerified;
    public boolean mfaEnabled;
    public boolean accountLocked;
    public boolean accountEnabled;
    public int failedLoginAttempts;
    public int failedMfaAttempts;
}
