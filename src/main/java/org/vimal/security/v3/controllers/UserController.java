package org.vimal.security.v3.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.vimal.security.v3.dtos.*;
import org.vimal.security.v3.services.UserService;

import java.util.Map;

import static org.vimal.security.v3.enums.MfaType.DEFAULT_MFA;

@RestController
@RequestMapping("/api/v1/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegistrationDto dto) throws Exception {
        return userService.register(dto);
    }

    @GetMapping("/getSelfDetails")
    public ResponseEntity<UserSummaryDto> getSelfDetails() throws Exception {
        return ResponseEntity.ok(userService.getSelfDetails());
    }

    @PostMapping("/verifyEmail")
    public ResponseEntity<Map<String, Object>> verifyEmail(@RequestParam String emailVerificationToken) throws Exception {
        return ResponseEntity.ok(userService.verifyEmail(emailVerificationToken));
    }

    @PostMapping("/resend/emailVerification/link")
    public ResponseEntity<Map<String, String>> resendEmailVerificationLink(@RequestParam String usernameOrEmail) throws Exception {
        return ResponseEntity.ok(userService.resendEmailVerificationLink(usernameOrEmail));
    }

    @PostMapping("/forgot/password")
    public ResponseEntity<Map<String, Object>> forgotPassword(@RequestParam String usernameOrEmail) throws Exception {
        return userService.forgotPassword(usernameOrEmail);
    }

    @PostMapping("/forgot/password/methodSelection")
    public ResponseEntity<Map<String, String>> forgotPasswordMethodSelection(@RequestParam String usernameOrEmail,
                                                                             @RequestParam(defaultValue = DEFAULT_MFA) String method) throws Exception {
        return ResponseEntity.ok(userService.forgotPasswordMethodSelection(
                        usernameOrEmail,
                        method
                )
        );
    }

    @PostMapping("/reset/password")
    public ResponseEntity<Map<String, Object>> resetPassword(@RequestBody ResetPwdDto dto) throws Exception {
        return userService.resetPassword(dto);
    }

    @PostMapping("/change/password")
    public ResponseEntity<Map<String, Object>> changePassword(@RequestBody ChangePwdDto dto) throws Exception {
        return userService.changePassword(dto);
    }

    @PostMapping("/change/password/methodSelection")
    public ResponseEntity<Map<String, String>> changePasswordMethodSelection(@RequestParam String method) throws Exception {
        return ResponseEntity.ok(userService.changePasswordMethodSelection(method));
    }

    @PostMapping("/verify/change/password")
    public ResponseEntity<Map<String, Object>> verifyChangePassword(@RequestBody ChangePwdDto dto) throws Exception {
        return userService.verifyChangePassword(dto);
    }

    @PostMapping("/email/change/request")
    public ResponseEntity<Map<String, String>> emailChangeRequest(@RequestParam String newEmail) throws Exception {
        return ResponseEntity.ok(userService.emailChangeRequest(newEmail));
    }

    @PostMapping("/verify/email/change")
    public ResponseEntity<Map<String, Object>> verifyEmailChange(@RequestParam String newEmailOtp,
                                                                 @RequestParam String oldEmailOtp,
                                                                 @RequestParam String password) throws Exception {
        return ResponseEntity.ok(userService.verifyEmailChange(
                        newEmailOtp,
                        oldEmailOtp,
                        password
                )
        );
    }

    @DeleteMapping("/delete/account")
    public ResponseEntity<Map<String, Object>> deleteAccount(@RequestParam String password) throws Exception {
        return userService.deleteAccount(password);
    }

    @PostMapping("/delete/account/methodSelection")
    public ResponseEntity<Map<String, String>> deleteAccountMethodSelection(@RequestParam String method) throws Exception {
        return ResponseEntity.ok(userService.deleteAccountMethodSelection(method));
    }

    @DeleteMapping("/verify/delete/account")
    public ResponseEntity<Map<String, String>> verifyDeleteAccount(@RequestParam String otpTotp,
                                                                   @RequestParam String method) throws Exception {
        return ResponseEntity.ok(userService.verifyDeleteAccount(
                        otpTotp,
                        method
                )
        );
    }

    @PutMapping("/update/details")
    public ResponseEntity<Map<String, Object>> updateDetails(@RequestBody SelfUpdationDto dto) throws Exception {
        return userService.updateDetails(dto);
    }
}
