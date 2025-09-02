package org.vimal.security.v3.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.vimal.security.v3.dtos.RoleSummaryDto;
import org.vimal.security.v3.dtos.UserSummaryDto;
import org.vimal.security.v3.dtos.UserSummaryToCompanyUsersDto;
import org.vimal.security.v3.encryptordecryptors.GenericAesRandomEncryptorDecryptor;
import org.vimal.security.v3.encryptordecryptors.GenericAesStaticEncryptorDecryptor;
import org.vimal.security.v3.enums.MfaType;
import org.vimal.security.v3.models.PermissionModel;
import org.vimal.security.v3.models.RoleModel;
import org.vimal.security.v3.models.UserModel;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class MapperUtility {
    private final GenericAesStaticEncryptorDecryptor genericAesStaticEncryptorDecryptor;
    private final GenericAesRandomEncryptorDecryptor genericAesRandomEncryptorDecryptor;

    public UserSummaryDto toUserSummaryDto(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserSummaryDto dto = new UserSummaryDto();
        mapCommonFields(user, dto);
        return dto;
    }

    public UserSummaryToCompanyUsersDto toUserSummaryToCompanyUsersDto(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserSummaryToCompanyUsersDto dto = new UserSummaryToCompanyUsersDto();
        mapCommonFields(user, dto);
        dto.setRealEmail(genericAesStaticEncryptorDecryptor.decrypt(user.getEmail(), String.class));
        dto.setAccountDeleted(user.isAccountDeleted());
        dto.setAccountDeletedAt(user.getAccountDeletedAt());
        dto.setAccountDeletedBy(user.getAccountDeletedBy() == null ? null : genericAesRandomEncryptorDecryptor.decrypt(user.getAccountDeletedBy(), String.class));
        dto.setAccountRecoveredAt(user.getAccountRecoveredAt());
        dto.setAccountRecoveredBy(user.getAccountRecoveredBy() == null ? null : genericAesRandomEncryptorDecryptor.decrypt(user.getAccountRecoveredBy(), String.class));
        return dto;
    }

    private void mapCommonFields(UserModel user, UserSummaryDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        dto.setId(user.getId());
        dto.setFirstName(user.getFirstName());
        dto.setMiddleName(user.getMiddleName());
        dto.setLastName(user.getLastName());
        dto.setUsername(genericAesStaticEncryptorDecryptor.decrypt(user.getUsername(), String.class));
        dto.setEmail(genericAesStaticEncryptorDecryptor.decrypt(user.getEmail(), String.class));
        dto.setCreatedBy(genericAesRandomEncryptorDecryptor.decrypt(user.getCreatedBy(), String.class));
        dto.setUpdatedBy(genericAesRandomEncryptorDecryptor.decrypt(user.getUpdatedBy(), String.class));
        Set<String> roles = new HashSet<>();
        if (user.getRoles() != null) {
            for (RoleModel role : user.getRoles()) {
                roles.add(role.getRoleName());
            }
        }
        dto.setRoles(roles);
        dto.setMfaEnabled(user.isMfaEnabled());
        Set<String> mfaMethods = new HashSet<>();
        if (user.getMfaMethods() != null) {
            for (MfaType mfa : user.getMfaMethods()) {
                mfaMethods.add(mfa.name());
            }
        }
        dto.setMfaMethods(mfaMethods);
        dto.setLastLoginAt(user.getLoginAt());
        dto.setPasswordChangedAt(user.getPasswordChangedAt());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setUpdatedAt(user.getUpdatedAt());
        dto.setLastLockedAt(user.getLockedAt());
        dto.setEmailVerified(user.isEmailVerified());
        dto.setAccountLocked(user.isAccountLocked());
        dto.setAccountEnabled(user.isAccountEnabled());
        dto.setFailedLoginAttempts(user.getFailedLoginAttempts());
        dto.setFailedMfaAttempts(user.getFailedMfaAttempts());
    }

    public RoleSummaryDto toRoleSummaryDto(RoleModel role) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        RoleSummaryDto dto = new RoleSummaryDto();
        dto.setRoleName(role.getRoleName());
        dto.setDescription(role.getDescription());
        dto.setCreatedBy(genericAesRandomEncryptorDecryptor.decrypt(role.getCreatedBy(), String.class));
        dto.setUpdatedBy(genericAesRandomEncryptorDecryptor.decrypt(role.getUpdatedBy(), String.class));
        Set<String> permissions = new HashSet<>();
        for (PermissionModel permission : role.getPermissions()) {
            permissions.add(permission.getPermissionName());
        }
        dto.setPermissions(permissions);
        dto.setCreatedAt(role.getCreatedAt());
        dto.setUpdatedAt(role.getUpdatedAt());
        dto.setSystemRole(role.isSystemRole());
        return dto;
    }
}
