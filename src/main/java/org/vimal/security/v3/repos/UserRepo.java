package org.vimal.security.v3.repos;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.vimal.security.v3.models.UserModel;

import java.util.Set;
import java.util.UUID;

@Repository
public interface UserRepo extends JpaRepository<UserModel, UUID> {
    UserModel findByUsername(String username);

    UserModel findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByRealEmail(String realEmail);

    Set<UserModel> findByUsernameIn(Set<String> usernames);

    Set<UserModel> findByEmailIn(Set<String> emails);
}
