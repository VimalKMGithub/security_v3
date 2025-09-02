package org.vimal.security.v3.services;

import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v3.repos.PermissionRepo;
import org.vimal.security.v3.repos.RoleRepo;
import org.vimal.security.v3.repos.UserRepo;
import org.vimal.security.v3.utils.AccessTokenUtility;

@Service
@RequiredArgsConstructor
public class AdminService {
    private static final int DEFAULT_MAX_USERS_TO_CREATE_AT_A_TIME = 100;
    private static final int DEFAULT_MAX_USERS_TO_DELETE_AT_A_TIME = 100;
    private static final int DEFAULT_MAX_USERS_TO_READ_AT_A_TIME = 300;
    private static final int DEFAULT_MAX_USERS_TO_UPDATE_AT_A_TIME = 100;
    private static final int DEFAULT_MAX_ROLES_TO_CREATE_AT_A_TIME = 100;
    private static final int DEFAULT_MAX_ROLES_TO_DELETE_AT_A_TIME = 100;
    private static final int DEFAULT_MAX_ROLES_TO_READ_AT_A_TIME = 300;
    private static final int DEFAULT_MAX_ROLES_TO_UPDATE_AT_A_TIME = 100;
    private static final int DEFAULT_MAX_PERMISSIONS_TO_READ_AT_A_TIME = 300;
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PermissionRepo permissionRepo;
    private final PasswordEncoder passwordEncoder;
    private final Unleash unleash;
    private final AccessTokenUtility accessTokenUtility;
}
