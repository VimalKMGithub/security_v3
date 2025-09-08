package org.vimal.security.v3.impls;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.vimal.security.v3.configs.PropertiesConfig;
import org.vimal.security.v3.dtos.SystemUserDto;
import org.vimal.security.v3.encryptordecryptors.GenericAesRandomEncryptorDecryptor;
import org.vimal.security.v3.encryptordecryptors.GenericAesStaticEncryptorDecryptor;
import org.vimal.security.v3.enums.SystemPermissions;
import org.vimal.security.v3.enums.SystemRoles;
import org.vimal.security.v3.models.PermissionModel;
import org.vimal.security.v3.models.RoleModel;
import org.vimal.security.v3.models.UserModel;
import org.vimal.security.v3.repos.PermissionRepo;
import org.vimal.security.v3.repos.RoleRepo;
import org.vimal.security.v3.repos.UserRepo;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.vimal.security.v3.enums.SystemPermissions.*;
import static org.vimal.security.v3.enums.SystemRoles.*;
import static org.vimal.security.v3.utils.EmailUtility.normalizeEmail;

@Slf4j
@Component
@RequiredArgsConstructor
public class CommandLineRunnerImpl implements CommandLineRunner {
    private final PropertiesConfig propertiesConfig;
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PermissionRepo permissionRepo;
    private final PasswordEncoder passwordEncoder;
    private final GenericAesStaticEncryptorDecryptor genericAesStaticEncryptorDecryptor;
    private final GenericAesRandomEncryptorDecryptor genericAesRandomEncryptorDecryptor;

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void run(String... args) throws Exception {
        log.info("Initializing system permissions, roles, and default users.");
        initializeSystemPermissionsIfAbsent();
        initializeSystemRolesIfAbsent();
        initializeDefaultUsersIfAbsent();
        log.info("System permissions, roles, and default users initialized successfully.");
    }

    private void initializeSystemPermissionsIfAbsent() throws Exception {
        Set<String> permissionNames = new HashSet<>();
        for (SystemPermissions permission : SystemPermissions.values()) {
            permissionNames.add(permission.name());
        }
        Set<String> existingPermissions = new HashSet<>();
        for (PermissionModel p : permissionRepo.findAllById(permissionNames)) {
            existingPermissions.add(p.getPermissionName());
        }
        Set<PermissionModel> newPermissions = new HashSet<>();
        for (String name : permissionNames) {
            if (!existingPermissions.contains(name)) {
                newPermissions.add(PermissionModel.builder()
                        .permissionName(name)
                        .createdBy(genericAesRandomEncryptorDecryptor.encrypt("SYSTEM"))
                        .build());
            }
        }
        if (!newPermissions.isEmpty()) {
            permissionRepo.saveAll(newPermissions);
        }
    }

    private void initializeSystemRolesIfAbsent() throws Exception {
        Set<String> roleNames = new HashSet<>();
        Map<String, Set<String>> rolePermissionsMap = new HashMap<>();
        for (SystemRoles role : SystemRoles.values()) {
            roleNames.add(role.name());
            rolePermissionsMap.put(role.name(), new HashSet<>());
        }
        addPermissionsToRoles(rolePermissionsMap);
        Set<String> allRequiredPermissions = new HashSet<>();
        for (Map.Entry<String, Set<String>> entry : rolePermissionsMap.entrySet()) {
            if (!entry.getValue()
                    .isEmpty()) {
                allRequiredPermissions.addAll(entry.getValue());
            }
        }
        Set<String> existingRoles = new HashSet<>();
        for (RoleModel r : roleRepo.findAllById(roleNames)) {
            existingRoles.add(r.getRoleName());
        }
        Map<String, PermissionModel> permissionsMap = new HashMap<>();
        for (PermissionModel p : permissionRepo.findAllById(allRequiredPermissions)) {
            permissionsMap.put(p.getPermissionName(), p);
        }
        Set<RoleModel> newRoles = new HashSet<>();
        for (Map.Entry<String, Set<String>> entry : rolePermissionsMap.entrySet()) {
            if (!existingRoles.contains(entry.getKey())) {
                Set<PermissionModel> permissions = new HashSet<>();
                for (String permissionName : entry.getValue()) {
                    PermissionModel permissionModel = permissionsMap.get(permissionName);
                    if (permissionModel != null) {
                        permissions.add(permissionModel);
                    }
                }
                newRoles.add(RoleModel.builder()
                        .roleName(entry.getKey())
                        .systemRole(true)
                        .permissions(permissions)
                        .createdBy(genericAesRandomEncryptorDecryptor.encrypt("SYSTEM"))
                        .build());
            }
        }
        if (!newRoles.isEmpty()) {
            roleRepo.saveAll(newRoles);
        }
    }

    private void addPermissionsToRoles(Map<String, Set<String>> rolePermissionsMap) {
        rolePermissionsMap.put(
                ROLE_MANAGE_USERS.name(),
                Set.of(
                        CAN_CREATE_USER.name(),
                        CAN_READ_USER.name(),
                        CAN_UPDATE_USER.name(),
                        CAN_DELETE_USER.name()
                )
        );
        rolePermissionsMap.put(
                ROLE_MANAGE_ROLES.name(),
                Set.of(
                        CAN_CREATE_ROLE.name(),
                        CAN_READ_ROLE.name(),
                        CAN_UPDATE_ROLE.name(),
                        CAN_DELETE_ROLE.name()
                )
        );
        rolePermissionsMap.put(
                ROLE_MANAGE_PERMISSIONS.name(),
                Set.of(CAN_READ_PERMISSION.name())
        );
    }

    private void initializeDefaultUsersIfAbsent() throws Exception {
        Set<SystemUserDto> systemUsers = Set.of(
                new SystemUserDto(
                        propertiesConfig.getGodUserUsername(),
                        propertiesConfig.getGodUserPassword(),
                        propertiesConfig.getGodUserEmail(),
                        "God",
                        Set.of(ROLE_GOD.name())
                ),
                new SystemUserDto(
                        propertiesConfig.getGlobalAdminUserUsername(),
                        propertiesConfig.getGlobalAdminUserPassword(),
                        propertiesConfig.getGlobalAdminUserEmail(),
                        "Global Admin",
                        Set.of(ROLE_GLOBAL_ADMIN.name())
                )
        );
        Set<String> encryptedUsernames = new HashSet<>();
        Map<String, String> encryptedUsernameToUsernameMap = new HashMap<>();
        Map<String, String> usernameToEncryptedUsernameMap = new HashMap<>();
        Set<String> roles = new HashSet<>();
        String tempStr;
        for (SystemUserDto user : systemUsers) {
            tempStr = genericAesStaticEncryptorDecryptor.encrypt(user.getUsername());
            encryptedUsernames.add(tempStr);
            encryptedUsernameToUsernameMap.put(tempStr, user.getUsername());
            usernameToEncryptedUsernameMap.put(user.getUsername(), tempStr);
            if (!user.getRoles().isEmpty()) {
                roles.addAll(user.getRoles());
            }
        }
        Set<String> existingUsersUsernames = new HashSet<>();
        for (UserModel user : userRepo.findByUsernameIn(encryptedUsernames)) {
            existingUsersUsernames.add(encryptedUsernameToUsernameMap.get(user.getUsername()));
        }
        Map<String, RoleModel> roleMap = new HashMap<>();
        for (RoleModel roleModel : roleRepo.findAllById(roles)) {
            roleMap.put(roleModel.getRoleName(), roleModel);
        }
        Set<UserModel> newUsers = new HashSet<>();
        for (SystemUserDto user : systemUsers) {
            if (!existingUsersUsernames.contains(user.getUsername())) {
                Set<RoleModel> userRoles = new HashSet<>();
                for (String roleName : user.getRoles()) {
                    RoleModel roleModel = roleMap.get(roleName);
                    if (roleModel != null) {
                        userRoles.add(roleModel);
                    }
                }
                newUsers.add(UserModel.builder()
                        .username(usernameToEncryptedUsernameMap.get(user.getUsername()))
                        .email(genericAesStaticEncryptorDecryptor.encrypt(user.getEmail()))
                        .realEmail(genericAesStaticEncryptorDecryptor.encrypt(normalizeEmail(user.getEmail())))
                        .firstName(user.getFirstName())
                        .password(passwordEncoder.encode(user.getPassword()))
                        .roles(userRoles)
                        .emailVerified(true)
                        .createdBy(genericAesRandomEncryptorDecryptor.encrypt("SYSTEM"))
                        .build());
            }
        }
        if (!newUsers.isEmpty()) {
            userRepo.saveAll(newUsers);
        }
    }
}
