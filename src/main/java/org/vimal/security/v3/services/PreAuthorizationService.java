package org.vimal.security.v3.services;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.vimal.security.v3.enums.SystemPermissions.*;
import static org.vimal.security.v3.enums.SystemRoles.TOP_ROLES;
import static org.vimal.security.v3.utils.UserUtility.getAuthenticationOfCurrentAuthenticatedUser;

@Service("PreAuth")
public class PreAuthorizationService {
    private static final Set<String> TOP_ROLES_SET = topRolesSet();
    private static final Set<String> CAN_CREATE_USERS_SET = canCreateUsersSet();
    private static final Set<String> CAN_READ_USERS_SET = canReadUsersSet();
    private static final Set<String> CAN_UPDATE_USERS_SET = canUpdateUsersSet();
    private static final Set<String> CAN_DELETE_USERS_SET = canDeleteUsersSet();
    private static final Set<String> CAN_READ_PERMISSIONS_SET = canReadPermissionsSet();
    private static final Set<String> CAN_CREATE_ROLES_SET = canCreateRolesSet();
    private static final Set<String> CAN_READ_ROLES_SET = canReadRolesSet();
    private static final Set<String> CAN_UPDATE_ROLES_SET = canUpdateRolesSet();
    private static final Set<String> CAN_DELETE_ROLES_SET = canDeleteRolesSet();

    private static Set<String> topRolesSet() {
        Set<String> set = new HashSet<>(TOP_ROLES);
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canCreateUsersSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_CREATE_USER.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canReadUsersSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_READ_USER.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canUpdateUsersSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_UPDATE_USER.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canDeleteUsersSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_DELETE_USER.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canReadPermissionsSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_READ_PERMISSION.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canCreateRolesSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_CREATE_ROLE.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canReadRolesSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_READ_ROLE.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canUpdateRolesSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_UPDATE_ROLE.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canDeleteRolesSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_DELETE_ROLE.name());
        return Collections.unmodifiableSet(set);
    }

    public boolean canCreateUsers() {
        return hasAnyAuthority(CAN_CREATE_USERS_SET);
    }

    public boolean canReadUsers() {
        return hasAnyAuthority(CAN_READ_USERS_SET);
    }

    public boolean canUpdateUsers() {
        return hasAnyAuthority(CAN_UPDATE_USERS_SET);
    }

    public boolean canDeleteUsers() {
        return hasAnyAuthority(CAN_DELETE_USERS_SET);
    }

    public boolean canReadPermissions() {
        return hasAnyAuthority(CAN_READ_PERMISSIONS_SET);
    }

    public boolean canCreateRoles() {
        return hasAnyAuthority(CAN_CREATE_ROLES_SET);
    }

    public boolean canReadRoles() {
        return hasAnyAuthority(CAN_READ_ROLES_SET);
    }

    public boolean canUpdateRoles() {
        return hasAnyAuthority(CAN_UPDATE_ROLES_SET);
    }

    public boolean canDeleteRoles() {
        return hasAnyAuthority(CAN_DELETE_ROLES_SET);
    }

    public boolean hasAnyAuthority(Set<String> authorities) {
        for (GrantedAuthority grantedAuthority : getAuthenticationOfCurrentAuthenticatedUser().getAuthorities()) {
            if (authorities.contains(grantedAuthority.getAuthority())) {
                return true;
            }
        }
        return false;
    }
}
