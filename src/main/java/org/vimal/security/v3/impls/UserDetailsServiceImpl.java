package org.vimal.security.v3.impls;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.vimal.security.v3.exceptions.EmailNotVerifiedException;
import org.vimal.security.v3.models.UserModel;
import org.vimal.security.v3.repos.UserRepo;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Component
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepo userRepo;

    @Override
    public UserDetailsImpl loadUserByUsername(String username) throws UsernameNotFoundException {
        UserModel user = userRepo.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("Invalid credentials");
        }
        checkUser(user);
        return new UserDetailsImpl(user);
    }

    private void checkUser(UserModel user) {
        if (user.isAccountDeleted()) {
            throw new UsernameNotFoundException("Invalid credentials");
        }
        if (!user.isEmailVerified()) {
            throw new EmailNotVerifiedException("Please verify your email");
        }
        if (user.isAccountLocked() &&
                user.getLockedAt()
                        .plus(
                                1,
                                ChronoUnit.DAYS
                        )
                        .isAfter(Instant.now())) {
            throw new LockedException("Account is temporarily locked. Please try again later.");
        }
    }
}
