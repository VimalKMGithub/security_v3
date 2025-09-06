package org.vimal.security.v3.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.vimal.security.v3.enums.MfaType;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users",
        indexes = {
                @Index(
                        name = "idx_username",
                        columnList = "username",
                        unique = true
                ),
                @Index(
                        name = "idx_email",
                        columnList = "email",
                        unique = true
                ),
                @Index(
                        name = "idx_real_email",
                        columnList = "realEmail",
                        unique = true
                )
        },
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_users_username",
                        columnNames = "username"
                ),
                @UniqueConstraint(
                        name = "uk_users_email",
                        columnNames = "email"
                ),
                @UniqueConstraint(
                        name = "uk_users_real_email",
                        columnNames = "realEmail"
                )
        })
@Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class UserModel {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(columnDefinition = "UUID",
            updatable = false,
            nullable = false,
            unique = true)
    private UUID id;

    @Column(name = "first_name",
            nullable = false,
            length = 50)
    private String firstName;

    @Column(name = "middle_name",
            length = 50)
    private String middleName;

    @Column(name = "last_name",
            length = 50)
    private String lastName;

    @Column(name = "username",
            nullable = false,
            unique = true,
            length = 512)
    private String username;

    @JsonIgnore
    @Column(name = "password",
            nullable = false,
            length = 512)
    private String password;

    @Column(name = "email",
            nullable = false,
            unique = true,
            length = 512)
    private String email;

    @JsonIgnore
    @Column(name = "real_email",
            nullable = false,
            unique = true,
            length = 512)
    private String realEmail;

    @Builder.Default
    @Column(name = "email_verified",
            nullable = false)
    private boolean emailVerified = false;

    @Builder.Default
    @Column(name = "mfa_enabled",
            nullable = false)
    private boolean mfaEnabled = false;

    @Builder.Default
    @Column(name = "account_locked",
            nullable = false)
    private boolean accountLocked = false;

    @Builder.Default
    @Column(name = "account_enabled",
            nullable = false)
    private boolean accountEnabled = true;

    @JsonIgnore
    @Builder.Default
    @Column(name = "account_deleted",
            nullable = false)
    private boolean accountDeleted = false;

    @JsonIgnore
    @Column(name = "account_deleted_at")
    private Instant accountDeletedAt;

    @JsonIgnore
    @Column(name = "account_deleted_by",
            length = 512)
    private String accountDeletedBy;

    @JsonIgnore
    @Column(name = "account_recovered_at")
    private Instant accountRecoveredAt;

    @JsonIgnore
    @Column(name = "account_recovered_by",
            length = 512)
    private String accountRecoveredBy;

    @JsonIgnore
    @Column(name = "auth_app_secret",
            length = 512)
    private String authAppSecret;

    public void recordAccountDeletionStatus(boolean isDeleted,
                                            String agentUsername) {
        if (isDeleted) {
            this.accountDeleted = true;
            this.accountDeletedAt = Instant.now();
            this.accountDeletedBy = agentUsername;
        } else {
            this.accountDeleted = false;
            this.accountRecoveredAt = Instant.now();
            this.accountRecoveredBy = agentUsername;
        }
    }

    @ManyToMany(fetch = FetchType.EAGER,
            cascade = {
                    CascadeType.PERSIST,
                    CascadeType.MERGE
            })
    @JoinTable(name = "user_roles",
            joinColumns = @JoinColumn(
                    name = "user_id",
                    referencedColumnName = "id"
            ),
            inverseJoinColumns = @JoinColumn(
                    name = "role_name",
                    referencedColumnName = "role_name"
            )
    )
    private Set<RoleModel> roles;

    @Column(name = "login_at")
    private Instant loginAt;

    @Column(name = "locked_at")
    private Instant lockedAt;

    public void recordLockedStatus(boolean locked) {
        this.accountLocked = locked;
        this.lockedAt = locked ? Instant.now() : null;
        if (!locked) {
            this.failedLoginAttempts = 0;
            this.failedMfaAttempts = 0;
        }
    }

    @Builder.Default
    @Column(name = "failed_login_attempts",
            nullable = false)
    private int failedLoginAttempts = 0;

    @Builder.Default
    @Column(name = "failed_mfa_attempts",
            nullable = false)
    private int failedMfaAttempts = 0;

    @Column(name = "password_changed_at",
            nullable = false)
    private Instant passwordChangedAt;

    public void recordPasswordChange(String newPassword) {
        this.password = newPassword;
        this.passwordChangedAt = Instant.now();
        this.failedLoginAttempts = 0;
        this.failedMfaAttempts = 0;
    }

    @Column(name = "created_at",
            updatable = false,
            nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    @Column(name = "created_by",
            nullable = false,
            updatable = false,
            length = 512)
    private String createdBy;

    @Column(name = "updated_by",
            length = 512)
    private String updatedBy;

    @PrePersist
    public void recordCreation() {
        Instant now = Instant.now();
        this.createdAt = now;
        this.passwordChangedAt = now;
    }

    public void recordUpdation(String updator) {
        this.updatedAt = Instant.now();
        this.updatedBy = updator;
    }

    public void recordSuccessfulLogin() {
        this.loginAt = Instant.now();
        this.failedLoginAttempts = 0;
        this.failedMfaAttempts = 0;
        this.accountLocked = false;
    }

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int UPPER_MAX_FAILED_ATTEMPTS = 10;
    private static final int MAX_FAILED_MFA_ATTEMPTS = 3;
    private static final int UPPER_MAX_FAILED_MFA_ATTEMPTS = 5;

    public void recordFailedLoginAttempt() {
        this.failedLoginAttempts++;
        if (this.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
            this.accountLocked = true;
            this.lockedAt = Instant.now();
        }
        if (this.failedLoginAttempts >= UPPER_MAX_FAILED_ATTEMPTS) {
            this.accountEnabled = false;
        }
    }

    public void recordFailedMfaAttempt() {
        this.failedMfaAttempts++;
        if (this.failedMfaAttempts >= MAX_FAILED_MFA_ATTEMPTS) {
            this.accountLocked = true;
            this.lockedAt = Instant.now();
        }
        if (this.failedMfaAttempts >= UPPER_MAX_FAILED_MFA_ATTEMPTS) {
            this.accountEnabled = false;
        }
    }

    @ElementCollection(targetClass = MfaType.class,
            fetch = FetchType.EAGER)
    @CollectionTable(name = "user_mfa_methods",
            joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "mfa_type",
            nullable = false)
    @Enumerated(EnumType.STRING)
    private Set<MfaType> mfaMethods;

    public void addMfaMethod(MfaType method) {
        this.mfaMethods.add(method);
        this.mfaEnabled = true;
    }

    public void removeMfaMethod(MfaType method) {
        this.mfaMethods.remove(method);
        this.mfaEnabled = !this.mfaMethods.isEmpty();
    }

    public boolean hasMfaMethod(MfaType method) {
        return this.mfaMethods.contains(method);
    }
}
