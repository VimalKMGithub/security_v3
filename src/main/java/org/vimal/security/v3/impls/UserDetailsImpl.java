package org.vimal.security.v3.impls;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.vimal.security.v3.models.PermissionModel;
import org.vimal.security.v3.models.RoleModel;
import org.vimal.security.v3.models.UserModel;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Set;

public class UserDetailsImpl implements UserDetails {
    @Getter
    private final UserModel user;
    private final Set<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(UserModel user) {
        this.user = user;
        this.authorities = extractAuthorities(user);
    }

    public UserDetailsImpl(UserModel user,
                           Set<? extends GrantedAuthority> authorities) {
        this.user = user;
        this.authorities = authorities;
    }

    private Set<? extends GrantedAuthority> extractAuthorities(UserModel user) {
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        for (RoleModel role : user.getRoles()) {
            authorities.add(new SimpleGrantedAuthority(role.getRoleName()));
            for (PermissionModel permission : role.getPermissions()) {
                authorities.add(new SimpleGrantedAuthority(permission.getPermissionName()));
            }
        }
        return authorities;
    }

    @Override
    public Set<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return user.getCreatedAt()
                .plus(
                        36500,
                        ChronoUnit.DAYS
                )
                .isAfter(Instant.now());
    }

    @Override
    public boolean isAccountNonLocked() {
        return !user.isAccountLocked() ||
                user.getLockedAt()
                        .plus(
                                1,
                                ChronoUnit.DAYS
                        )
                        .isBefore(Instant.now());
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return user.getPasswordChangedAt()
                .plus(
                        365,
                        ChronoUnit.DAYS
                )
                .isAfter(Instant.now());
    }

    @Override
    public boolean isEnabled() {
        return user.isAccountEnabled();
    }
}
