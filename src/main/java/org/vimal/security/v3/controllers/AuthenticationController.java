package org.vimal.security.v3.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.vimal.security.v3.services.AuthenticationService;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestParam String usernameOrEmail,
                                                     @RequestParam String password) throws Exception {
        return ResponseEntity.ok(authenticationService.login(
                        usernameOrEmail,
                        password
                )
        );
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout() throws Exception {
        return ResponseEntity.ok(authenticationService.logout());
    }

    @PostMapping("/refresh/accessToken")
    public ResponseEntity<Map<String, Object>> refreshAccessToken(@RequestParam String refreshToken) throws Exception {
        return ResponseEntity.ok(authenticationService.refreshAccessToken(refreshToken));
    }

    @PostMapping("/revoke/accessToken")
    public ResponseEntity<Map<String, String>> revokeAccessToken() throws Exception {
        return ResponseEntity.ok(authenticationService.revokeAccessToken());
    }

    @PostMapping("/revoke/refreshToken")
    public ResponseEntity<Map<String, String>> revokeRefreshToken(@RequestParam String refreshToken) throws Exception {
        return ResponseEntity.ok(authenticationService.revokeRefreshToken(refreshToken));
    }

    @PostMapping("/mfa/requestTo/toggle")
    public ResponseEntity<Object> requestToToggleMfa(@RequestParam String type,
                                                     @RequestParam String toggle) throws Exception {
        return authenticationService.requestToToggleMfa(
                type,
                toggle
        );
    }

    @PostMapping("/mfa/verifyTo/toggle")
    public ResponseEntity<Map<String, String>> verifyToggleMfa(@RequestParam String type,
                                                               @RequestParam String toggle,
                                                               @RequestParam String otpTotp) throws Exception {
        return ResponseEntity.ok(authenticationService.verifyToggleMfa(
                        type,
                        toggle,
                        otpTotp
                )
        );
    }

    @PostMapping("/mfa/requestTo/login")
    public ResponseEntity<Map<String, String>> requestToLoginMfa(@RequestParam String type,
                                                                 @RequestParam String stateToken) throws Exception {
        return ResponseEntity.ok(authenticationService.requestToLoginMfa(
                        type,
                        stateToken
                )
        );
    }

    @PostMapping("/mfa/verifyTo/login")
    public ResponseEntity<Map<String, Object>> verifyMfaToLogin(@RequestParam String type,
                                                                @RequestParam String stateToken,
                                                                @RequestParam String otpTotp) throws Exception {
        return ResponseEntity.ok(authenticationService.verifyMfaToLogin(
                        type,
                        stateToken,
                        otpTotp
                )
        );
    }
}
