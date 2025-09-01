package org.vimal.security.v3.models;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.hibernate.annotations.NaturalId;

import java.time.Instant;

@Entity
@Table(name = "permissions",
        indexes = @Index(name = "idx_permission_name", columnList = "permission_name"),
        uniqueConstraints = @UniqueConstraint(name = "uk_permission_name", columnNames = "permission_name"))
@Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class PermissionModel {
    @Id
    @NaturalId
    @Column(name = "permission_name", nullable = false, updatable = false, length = 100)
    private String permissionName;

    @Column(name = "description")
    private String description;

    @Builder.Default
    @Column(name = "is_system_permission", nullable = false)
    private boolean systemPermission = false;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "created_by", nullable = false, updatable = false, length = 512)
    private String createdBy;

    @Column(name = "updated_by", nullable = false, length = 512)
    private String updatedBy;

    @PrePersist
    public void recordCreation() {
        Instant now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    public void recordUpdation(String updator) {
        this.updatedAt = Instant.now();
        this.updatedBy = updator;
    }
}
