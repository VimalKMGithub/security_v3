package org.vimal.security.v3.repos;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.vimal.security.v3.models.PermissionModel;

@Repository
public interface PermissionRepo extends JpaRepository<PermissionModel, String> {
}
