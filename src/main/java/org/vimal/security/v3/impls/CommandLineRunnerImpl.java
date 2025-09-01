package org.vimal.security.v3.impls;

import com.fasterxml.jackson.core.JsonProcessingException;
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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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
    private static final String SYSTEM = "SYSTEM";
    private final PropertiesConfig propertiesConfig;
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PermissionRepo permissionRepo;
    private final PasswordEncoder passwordEncoder;
    private final GenericAesStaticEncryptorDecryptor genericAesStaticEncryptorDecryptor;
    private final GenericAesRandomEncryptorDecryptor genericAesRandomEncryptorDecryptor;

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void run(String... args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        log.info("Initializing system permissions, roles, and default users.");
        initializeSystemPermissionsIfAbsent();
        initializeSystemRolesIfAbsent();
        initializeDefaultUsersIfAbsent();
        log.info("System permissions, roles, and default users initialized successfully.");
    }

    private void initializeSystemPermissionsIfAbsent() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
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
                        .systemPermission(true)
                        .createdBy(genericAesRandomEncryptorDecryptor.encrypt(SYSTEM))
                        .updatedBy(genericAesRandomEncryptorDecryptor.encrypt(SYSTEM))
                        .build());
            }
        }
        if (!newPermissions.isEmpty()) {
            permissionRepo.saveAll(newPermissions);
        }
    }

    private void initializeSystemRolesIfAbsent() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        Set<String> roleNames = new HashSet<>();
        Map<String, Set<String>> rolePermissionsMap = new HashMap<>();
        for (SystemRoles role : SystemRoles.values()) {
            roleNames.add(role.name());
            rolePermissionsMap.put(role.name(), new HashSet<>());
        }
        addPermissionsToRoles(rolePermissionsMap);
        Set<String> allRequiredPermissions = new HashSet<>();
        for (Map.Entry<String, Set<String>> entry : rolePermissionsMap.entrySet()) {
            if (!entry.getValue().isEmpty()) {
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
                    if (permissionsMap.containsKey(permissionName)) {
                        permissions.add(permissionsMap.get(permissionName));
                    }
                }
                newRoles.add(RoleModel.builder()
                        .roleName(entry.getKey())
                        .systemRole(true)
                        .permissions(permissions)
                        .createdBy(genericAesRandomEncryptorDecryptor.encrypt(SYSTEM))
                        .updatedBy(genericAesRandomEncryptorDecryptor.encrypt(SYSTEM))
                        .build());
            }
        }
        if (!newRoles.isEmpty()) {
            roleRepo.saveAll(newRoles);
        }
    }

    private void addPermissionsToRoles(Map<String, Set<String>> rolePermissionsMap) {
        rolePermissionsMap.put(ROLE_MANAGE_USERS.name(), Set.of(CAN_CREATE_USER.name(), CAN_READ_USER.name(), CAN_UPDATE_USER.name(), CAN_DELETE_USER.name()));
        rolePermissionsMap.put(ROLE_MANAGE_ROLES.name(), Set.of(CAN_CREATE_ROLE.name(), CAN_READ_ROLE.name(), CAN_UPDATE_ROLE.name(), CAN_DELETE_ROLE.name()));
        rolePermissionsMap.put(ROLE_MANAGE_PERMISSIONS.name(), Set.of(CAN_READ_PERMISSION.name()));
    }

    private void initializeDefaultUsersIfAbsent() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        Set<SystemUserDto> systemUsers = Set.of(new SystemUserDto(propertiesConfig.getGodUserUsername(), propertiesConfig.getGodUserPassword(), propertiesConfig.getGodUserEmail(), "God", Set.of(ROLE_GOD.name())), new SystemUserDto(propertiesConfig.getGlobalAdminUserUsername(), propertiesConfig.getGlobalAdminUserPassword(), propertiesConfig.getGlobalAdminUserEmail(), "Global Admin", Set.of(ROLE_GLOBAL_ADMIN.name())));
        Set<UserModel> existingUsers = userRepo.findByUsernameIn(Set.of(propertiesConfig.getGodUserUsername(), propertiesConfig.getGlobalAdminUserUsername()));
        Set<String> existingUsersUsernames = new HashSet<>();
        for (UserModel user : existingUsers) {
            existingUsersUsernames.add(genericAesStaticEncryptorDecryptor.decrypt(user.getUsername(), String.class));
        }
        Set<UserModel> newUsers = new HashSet<>();
        for (SystemUserDto user : systemUsers) {
            if (!existingUsersUsernames.contains(user.getUsername())) {
                newUsers.add(UserModel.builder()
                        .username(genericAesStaticEncryptorDecryptor.encrypt(user.getUsername()))
                        .email(genericAesStaticEncryptorDecryptor.encrypt(user.getEmail()))
                        .realEmail(genericAesStaticEncryptorDecryptor.encrypt(normalizeEmail(user.getEmail())))
                        .firstName(user.getFirstName())
                        .password(passwordEncoder.encode(user.getPassword()))
                        .roles(new HashSet<>(roleRepo.findAllById(user.getRoles())))
                        .emailVerified(true)
                        .createdBy(genericAesRandomEncryptorDecryptor.encrypt(SYSTEM))
                        .updatedBy(genericAesRandomEncryptorDecryptor.encrypt(SYSTEM))
                        .build());
            }
        }
        if (!newUsers.isEmpty()) {
            userRepo.saveAll(newUsers);
        }
    }
}
