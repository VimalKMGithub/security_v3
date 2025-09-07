package org.vimal.security.v3.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.vimal.security.v3.dtos.RoleCreationDto;
import org.vimal.security.v3.dtos.UserCreationDto;
import org.vimal.security.v3.dtos.UserUpdationDto;
import org.vimal.security.v3.services.AdminService;

import java.util.Map;
import java.util.Set;

import static org.vimal.security.v3.utils.ToggleUtility.DEFAULT_TOGGLE;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class AdminController {
    private final AdminService adminService;

    @PostMapping("/create/users")
    @PreAuthorize("@PreAuth.canCreateUsers()")
    public ResponseEntity<Map<String, Object>> createUsers(@RequestBody Set<UserCreationDto> dtos,
                                                           @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency) throws Exception {
        return adminService.createUsers(
                dtos,
                leniency
        );
    }

    @DeleteMapping("/delete/users")
    @PreAuthorize("@PreAuth.canDeleteUsers()")
    public ResponseEntity<Map<String, Object>> deleteUsers(@RequestBody Set<String> usernamesOrEmails,
                                                           @RequestParam(defaultValue = DEFAULT_TOGGLE) String hard,
                                                           @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency) throws Exception {
        return adminService.deleteUsers(
                usernamesOrEmails,
                hard,
                leniency
        );
    }

    @GetMapping("/read/users")
    @PreAuthorize("@PreAuth.canReadUsers()")
    public ResponseEntity<Map<String, Object>> readUsers(@RequestBody Set<String> usernamesOrEmails,
                                                         @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency) throws Exception {
        return adminService.readUsers(
                usernamesOrEmails,
                leniency
        );
    }

    @PutMapping("/update/users")
    @PreAuthorize("@PreAuth.canUpdateUsers()")
    public ResponseEntity<Map<String, Object>> updateUsers(@RequestBody Set<UserUpdationDto> dtos,
                                                           @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency) throws Exception {
        return adminService.updateUsers(
                dtos,
                leniency
        );
    }

    @PostMapping("/create/roles")
    @PreAuthorize("@PreAuth.canCreateRoles()")
    public ResponseEntity<Map<String, Object>> createRoles(@RequestBody Set<RoleCreationDto> dtos,
                                                           @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency) throws Exception {
        return adminService.createRoles(
                dtos,
                leniency
        );
    }

    @DeleteMapping("/delete/roles")
    @PreAuthorize("@PreAuth.canDeleteRoles()")
    public ResponseEntity<Map<String, Object>> deleteRoles(@RequestBody Set<String> roleNames,
                                                           @RequestParam(defaultValue = DEFAULT_TOGGLE) String force,
                                                           @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency) throws Exception {
        return adminService.deleteRoles(
                roleNames,
                force,
                leniency
        );
    }

    @GetMapping("/read/roles")
    @PreAuthorize("@PreAuth.canReadRoles()")
    public ResponseEntity<Map<String, Object>> readRoles(@RequestBody Set<String> roleNames,
                                                         @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency) throws Exception {
        return adminService.readRoles(
                roleNames,
                leniency
        );
    }

    @PutMapping("/update/roles")
    @PreAuthorize("@PreAuth.canUpdateRoles()")
    public ResponseEntity<Map<String, Object>> updateRoles(@RequestBody Set<RoleCreationDto> dtos,
                                                           @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency) throws Exception {
        return adminService.updateRoles(
                dtos,
                leniency
        );
    }

    @GetMapping("/read/permissions")
    @PreAuthorize("@PreAuth.canReadPermissions()")
    public ResponseEntity<Map<String, Object>> readPermissions(@RequestBody Set<String> permissionNames,
                                                               @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency) throws Exception {
        return adminService.readPermissions(
                permissionNames,
                leniency
        );
    }
}
