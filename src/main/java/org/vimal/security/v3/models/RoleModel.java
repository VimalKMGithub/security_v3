package org.vimal.security.v3.models;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.hibernate.annotations.NaturalId;

import java.time.Instant;
import java.util.Set;

@Entity
@Table(name = "roles",
        indexes = @Index(
                name = "idx_role_name",
                columnList = "role_name"
        ),
        uniqueConstraints = @UniqueConstraint(
                name = "uk_role_name",
                columnNames = "role_name"
        )
)
@Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class RoleModel {
    @Id
    @NaturalId
    @Column(name = "role_name",
            nullable = false,
            updatable = false,
            length = 100)
    private String roleName;

    @Column(name = "description")
    private String description;

    @Builder.Default
    @Column(name = "is_system_role",
            nullable = false)
    private boolean systemRole = false;

    @ManyToMany(fetch = FetchType.EAGER,
            cascade = {
                    CascadeType.PERSIST,
                    CascadeType.MERGE
            })
    @JoinTable(name = "role_permissions",
            joinColumns = @JoinColumn(
                    name = "role_name",
                    referencedColumnName = "role_name",
                    foreignKey = @ForeignKey(name = "fk_role_permissions_role")),
            inverseJoinColumns = @JoinColumn(
                    name = "permission_name",
                    referencedColumnName = "permission_name",
                    foreignKey = @ForeignKey(name = "fk_role_permissions_permission")))
    private Set<PermissionModel> permissions;

    @Column(name = "created_at",
            nullable = false,
            updatable = false)
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
        this.createdAt = Instant.now();
    }

    public void recordUpdation(String updator) {
        this.updatedAt = Instant.now();
        this.updatedBy = updator;
    }
}
