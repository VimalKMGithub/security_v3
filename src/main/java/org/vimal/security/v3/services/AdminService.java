package org.vimal.security.v3.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.getunleash.Unleash;
import io.getunleash.variant.Variant;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v3.dtos.*;
import org.vimal.security.v3.encryptordecryptors.GenericAesRandomEncryptorDecryptor;
import org.vimal.security.v3.encryptordecryptors.GenericAesStaticEncryptorDecryptor;
import org.vimal.security.v3.exceptions.ServiceUnavailableException;
import org.vimal.security.v3.exceptions.SimpleBadRequestException;
import org.vimal.security.v3.impls.UserDetailsImpl;
import org.vimal.security.v3.models.RoleModel;
import org.vimal.security.v3.models.UserModel;
import org.vimal.security.v3.repos.PermissionRepo;
import org.vimal.security.v3.repos.RoleRepo;
import org.vimal.security.v3.repos.UserRepo;
import org.vimal.security.v3.utils.AccessTokenUtility;
import org.vimal.security.v3.utils.MapperUtility;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;

import static org.vimal.security.v3.enums.FeatureFlags.*;
import static org.vimal.security.v3.enums.SystemRoles.ROLE_PRIORITY_MAP;
import static org.vimal.security.v3.enums.SystemRoles.TOP_ROLES;
import static org.vimal.security.v3.utils.UserUtility.getCurrentAuthenticatedUserDetails;
import static org.vimal.security.v3.utils.ValidationUtility.*;

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
    private final MapperUtility mapperUtility;
    private final AccessTokenUtility accessTokenUtility;
    private final GenericAesStaticEncryptorDecryptor genericAesStaticEncryptorDecryptor;
    private final GenericAesRandomEncryptorDecryptor genericAesRandomEncryptorDecryptor;

    public ResponseEntity<Map<String, Object>> createUsers(Set<UserCreationDto> dtos) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserDetailsImpl creator = getCurrentAuthenticatedUserDetails();
        String creatorHighestTopRole = getUserHighestTopRole(creator);
        Variant variant = unleash.getVariant(ALLOW_CREATE_USERS.name());
        if (entryCheck(variant, creatorHighestTopRole)) {
            checkUserCanCreateUsers(creatorHighestTopRole);
            validateDtosSizeForUsersCreation(variant, dtos);
            ValidateInputsForUsersCreationResultDto validateInputsForUsersCreationResult = validateInputsForUsersCreation(dtos, creatorHighestTopRole);
            Map<String, Object> mapOfErrors = errorsStuffingIfAny(validateInputsForUsersCreationResult);
            if (!mapOfErrors.isEmpty()) {
                return ResponseEntity.badRequest().body(mapOfErrors);
            }
            AlreadyTakenUsernamesAndEmailsResultDto alreadyTakenUsernamesAndEmailsResult = getAlreadyTakenUsernamesAndEmails(validateInputsForUsersCreationResult);
            Map<String, RoleModel> resolvedRolesMap = resolveRoles(validateInputsForUsersCreationResult.getRoles());
            if (!alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenUsernames().isEmpty()) {
                mapOfErrors.put("already_taken_usernames", alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenUsernames());
            }
            if (!alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenEmails().isEmpty()) {
                mapOfErrors.put("already_taken_emails", alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenEmails());
            }
            if (!validateInputsForUsersCreationResult.getRoles().isEmpty()) {
                mapOfErrors.put("missing_roles", validateInputsForUsersCreationResult.getRoles());
            }
            if (!mapOfErrors.isEmpty()) {
                return ResponseEntity.badRequest().body(mapOfErrors);
            }
            if (dtos.isEmpty()) {
                return ResponseEntity.ok(Map.of("message", "No users to create"));
            }
            Set<UserModel> newUsers = new HashSet<>();
            for (UserCreationDto dto : dtos) {
                if (dto.getRoles() == null || dto.getRoles().isEmpty()) {
                    newUsers.add(toUserModel(dto, new HashSet<>(), creator.getUsername()));
                } else {
                    Set<RoleModel> rolesToAssign = new HashSet<>();
                    for (String roleName : dto.getRoles()) {
                        RoleModel role = resolvedRolesMap.get(roleName);
                        if (role != null) {
                            rolesToAssign.add(role);
                        }
                    }
                    newUsers.add(toUserModel(dto, rolesToAssign, creator.getUsername()));
                }
            }
            List<UserSummaryToCompanyUsersDto> users = new ArrayList<>();
            for (UserModel userModel : userRepo.saveAll(newUsers)) {
                users.add(mapperUtility.toUserSummaryToCompanyUsersDto(userModel));
            }
            return ResponseEntity.ok(Map.of("created_users", users));
        }
        throw new ServiceUnavailableException("Creation of new users is currently disabled. Please try again later");
    }

    private String getUserHighestTopRole(UserDetailsImpl userDetails) {
        String bestRole = null;
        int bestPriority = Integer.MAX_VALUE;
        String tempAuthority;
        Integer tempPriority;
        for (GrantedAuthority authority : userDetails.getAuthorities()) {
            tempAuthority = authority.getAuthority();
            tempPriority = ROLE_PRIORITY_MAP.get(tempAuthority);
            if (tempPriority != null && tempPriority < bestPriority) {
                bestPriority = tempPriority;
                bestRole = tempAuthority;
            }
        }
        return bestRole;
    }

    private boolean entryCheck(Variant variant, String userHighestTopRole) {
        return variant.isEnabled() || TOP_ROLES.getFirst().equals(userHighestTopRole);
    }

    private void checkUserCanCreateUsers(String userHighestTopRole) {
        if (userHighestTopRole == null && !unleash.isEnabled(ALLOW_CREATE_USERS_BY_USERS_HAVE_PERMISSION_TO_CREATE_USERS.name())) {
            throw new ServiceUnavailableException("Creation of new users is currently disabled. Please try again later");
        }
    }

    private void validateDtosSizeForUsersCreation(Variant variant, Set<UserCreationDto> dtos) {
        if (dtos.isEmpty()) {
            throw new SimpleBadRequestException("No users to create");
        }
        if (variant.isEnabled() && variant.getPayload().isPresent()) {
            int maxUsersToCreateAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
            if (maxUsersToCreateAtATime < 1) {
                maxUsersToCreateAtATime = DEFAULT_MAX_USERS_TO_CREATE_AT_A_TIME;
            }
            if (dtos.size() > maxUsersToCreateAtATime) {
                throw new SimpleBadRequestException("Cannot create more than " + maxUsersToCreateAtATime + " users at a time");
            }
        } else if (dtos.size() > DEFAULT_MAX_USERS_TO_CREATE_AT_A_TIME) {
            throw new SimpleBadRequestException("Cannot create more than " + DEFAULT_MAX_USERS_TO_CREATE_AT_A_TIME + " users at a time");
        }
    }

    private ValidateInputsForUsersCreationResultDto validateInputsForUsersCreation(Set<UserCreationDto> dtos, String creatorHighestTopRole) {
        Set<String> invalidInputs = new HashSet<>();
        Set<String> usernames = new HashSet<>();
        Set<String> emails = new HashSet<>();
        Set<String> duplicateUsernamesInDtos = new HashSet<>();
        Set<String> duplicateEmailsInDtos = new HashSet<>();
        Set<String> roles = new HashSet<>();
        Set<String> restrictedRoles = new HashSet<>();
        dtos.remove(null);
        Iterator<UserCreationDto> iterator = dtos.iterator();
        Set<String> tempSet;
        UserCreationDto tempDto;
        boolean removeFromDtos;
        while (iterator.hasNext()) {
            removeFromDtos = false;
            tempDto = iterator.next();
            tempSet = validateInputs(tempDto);
            if (!tempSet.isEmpty()) {
                invalidInputs.addAll(tempSet);
                removeFromDtos = true;
            }
            if (tempDto.getUsername() != null && USERNAME_PATTERN.matcher(tempDto.getUsername()).matches() && !usernames.add(tempDto.getUsername())) {
                duplicateUsernamesInDtos.add(tempDto.getUsername());
                removeFromDtos = true;
            }
            if (tempDto.getEmail() != null && EMAIL_PATTERN.matcher(tempDto.getEmail()).matches() && !emails.add(tempDto.getEmail())) {
                duplicateEmailsInDtos.add(tempDto.getEmail());
                removeFromDtos = true;
            }
            if (tempDto.getRoles() != null && !tempDto.getRoles().isEmpty()) {
                removeFromDtos = sanitizeRoles(tempDto.getRoles(), restrictedRoles, creatorHighestTopRole);
                if (!tempDto.getRoles().isEmpty()) {
                    roles.addAll(tempDto.getRoles());
                }
            }
            if (removeFromDtos) {
                iterator.remove();
            }
        }
        return new ValidateInputsForUsersCreationResultDto(invalidInputs, usernames, emails, duplicateUsernamesInDtos, duplicateEmailsInDtos, roles, restrictedRoles);
    }

    private boolean sanitizeRoles(Set<String> roles, Set<String> restrictedRoles, String userHighestTopRole) {
        roles.remove(null);
        Iterator<String> iterator = roles.iterator();
        boolean removeFromDtos = false;
        String temp;
        while (iterator.hasNext()) {
            temp = iterator.next();
            if (temp.isBlank()) {
                iterator.remove();
            } else {
                if (!TOP_ROLES.getFirst().equals(userHighestTopRole)) {
                    if (ROLE_PRIORITY_MAP.containsKey(temp)) {
                        if (userHighestTopRole == null || ROLE_PRIORITY_MAP.get(temp) <= ROLE_PRIORITY_MAP.get(userHighestTopRole)) {
                            restrictedRoles.add(temp);
                            removeFromDtos = true;
                        }
                    }
                }
            }
        }
        return removeFromDtos;
    }

    private Map<String, Object> errorsStuffingIfAny(ValidateInputsForUsersCreationResultDto validateInputsForUsersCreationResult) {
        Map<String, Object> mapOfErrors = new HashMap<>();
        if (!validateInputsForUsersCreationResult.getInvalidInputs().isEmpty()) {
            mapOfErrors.put("invalid_inputs", validateInputsForUsersCreationResult.getInvalidInputs());
        }
        if (!validateInputsForUsersCreationResult.getDuplicateUsernamesInDtos().isEmpty()) {
            mapOfErrors.put("duplicate_usernames_in_request", validateInputsForUsersCreationResult.getDuplicateUsernamesInDtos());
        }
        if (!validateInputsForUsersCreationResult.getDuplicateEmailsInDtos().isEmpty()) {
            mapOfErrors.put("duplicate_emails_in_request", validateInputsForUsersCreationResult.getDuplicateEmailsInDtos());
        }
        if (!validateInputsForUsersCreationResult.getRestrictedRoles().isEmpty()) {
            mapOfErrors.put("not_allowed_to_assign_roles", validateInputsForUsersCreationResult.getRestrictedRoles());
        }
        return mapOfErrors;
    }

    private Map<String, RoleModel> resolveRoles(Set<String> roles) {
        if (roles == null || roles.isEmpty()) {
            return new HashMap<>();
        }
        Map<String, RoleModel> resolvedRolesMap = new HashMap<>();
        for (RoleModel role : roleRepo.findAllById(roles)) {
            roles.remove(role.getRoleName());
            resolvedRolesMap.put(role.getRoleName(), role);
        }
        return resolvedRolesMap;
    }

    private AlreadyTakenUsernamesAndEmailsResultDto getAlreadyTakenUsernamesAndEmails(ValidateInputsForUsersCreationResultDto validateInputsForUsersCreationResult) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        Set<String> tempSet = new HashSet<>();
        Map<String, String> tempMap = new HashMap<>();
        String tempStr;
        for (String username : validateInputsForUsersCreationResult.getUsernames()) {
            tempStr = genericAesStaticEncryptorDecryptor.encrypt(username);
            tempSet.add(tempStr);
            tempMap.put(tempStr, username);
        }
        Set<String> alreadyTakenUsernames = new HashSet<>();
        for (UserModel user : userRepo.findByUsernameIn(tempSet)) {
            alreadyTakenUsernames.add(tempMap.get(user.getUsername()));
        }
        tempSet.clear();
        tempMap.clear();
        for (String email : validateInputsForUsersCreationResult.getEmails()) {
            tempStr = genericAesStaticEncryptorDecryptor.encrypt(email);
            tempSet.add(tempStr);
            tempMap.put(tempStr, email);
        }
        Set<String> alreadyTakenEmails = new HashSet<>();
        for (UserModel user : userRepo.findByEmailIn(tempSet)) {
            alreadyTakenEmails.add(tempMap.get(user.getEmail()));
        }
        return new AlreadyTakenUsernamesAndEmailsResultDto(alreadyTakenUsernames, alreadyTakenEmails);
    }

    private UserModel toUserModel(UserCreationDto dto, Set<RoleModel> roles, String creator) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        String encryptedEmail = genericAesStaticEncryptorDecryptor.encrypt(dto.getEmail());
        String creatorDecrypted = genericAesStaticEncryptorDecryptor.decrypt(creator, String.class);
        return UserModel.builder()
                .username(genericAesStaticEncryptorDecryptor.encrypt(dto.getUsername()))
                .email(encryptedEmail)
                .realEmail(encryptedEmail)
                .password(passwordEncoder.encode(dto.getPassword()))
                .firstName(dto.getFirstName())
                .middleName(dto.getMiddleName())
                .lastName(dto.getLastName())
                .roles(roles)
                .emailVerified(dto.isEmailVerified())
                .accountEnabled(dto.isAccountEnabled())
                .accountLocked(dto.isAccountLocked())
                .lockedAt(dto.isAccountLocked() ? Instant.now() : null)
                .createdBy(genericAesRandomEncryptorDecryptor.encrypt(creatorDecrypted))
                .updatedBy(genericAesRandomEncryptorDecryptor.encrypt(creatorDecrypted))
                .accountDeleted(dto.isAccountDeleted())
                .accountDeletedAt(dto.isAccountDeleted() ? Instant.now() : null)
                .accountDeletedBy(dto.isAccountDeleted() ? genericAesRandomEncryptorDecryptor.encrypt(creator) : null)
                .build();
    }

    public ResponseEntity<Map<String, Object>> createUsersLenient(Set<UserCreationDto> dtos) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserDetailsImpl creator = getCurrentAuthenticatedUserDetails();
        String creatorHighestTopRole = getUserHighestTopRole(creator);
        Variant variant = unleash.getVariant(ALLOW_CREATE_USERS.name());
        if (entryCheck(variant, creatorHighestTopRole)) {
            checkUserCanCreateUsers(creatorHighestTopRole);
            validateDtosSizeForUsersCreation(variant, dtos);
            ValidateInputsForUsersCreationResultDto validateInputsForUsersCreationResult = validateInputsForUsersCreation(dtos, creatorHighestTopRole);
            AlreadyTakenUsernamesAndEmailsResultDto alreadyTakenUsernamesAndEmailsResult = getAlreadyTakenUsernamesAndEmails(validateInputsForUsersCreationResult);
            if (dtos.isEmpty()) {
                return ResponseEntity.ok(Map.of("message", "No users created"));
            }
            Map<String, RoleModel> resolvedRolesMap = resolveRoles(validateInputsForUsersCreationResult.getRoles());
            Set<UserModel> newUsers = new HashSet<>();
            for (UserCreationDto dto : dtos) {
                if (alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenUsernames().contains(dto.getUsername()) || alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenEmails().contains(dto.getEmail())) {
                    continue;
                }
                if (dto.getRoles() == null || dto.getRoles().isEmpty()) {
                    newUsers.add(toUserModel(dto, new HashSet<>(), creator.getUsername()));
                } else {
                    Set<RoleModel> rolesToAssign = new HashSet<>();
                    for (String roleName : dto.getRoles()) {
                        RoleModel role = resolvedRolesMap.get(roleName);
                        if (role != null) {
                            rolesToAssign.add(role);
                        }
                    }
                    newUsers.add(toUserModel(dto, rolesToAssign, creator.getUsername()));
                }
            }
            if (!newUsers.isEmpty()) {
                return ResponseEntity.ok(Map.of("message", "No users created"));
            }
            List<UserSummaryToCompanyUsersDto> users = new ArrayList<>();
            for (UserModel userModel : userRepo.saveAll(newUsers)) {
                users.add(mapperUtility.toUserSummaryToCompanyUsersDto(userModel));
            }
            return ResponseEntity.ok(Map.of("created_users", users));
        }
        throw new ServiceUnavailableException("Creation of new users is currently disabled. Please try again later");
    }

    public ResponseEntity<Map<String, Object>> deleteUsers(Set<String> usernamesOrEmails) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserDetailsImpl deleter = getCurrentAuthenticatedUserDetails();
        String deleterHighestTopRole = getUserHighestTopRole(deleter);
        ValidateInputsForDeleteUsersResultDto validateInputsForDeleteUsersResult = validateInputsForDeleteUsers(usernamesOrEmails, deleter, deleterHighestTopRole, false);
        if (validateInputsForDeleteUsersResult.getMapOfErrors().isEmpty()) {
            if (!validateInputsForDeleteUsersResult.getUsersToDelete().isEmpty()) {
                accessTokenUtility.revokeTokens(validateInputsForDeleteUsersResult.getUsersToDelete());
                userRepo.saveAll(validateInputsForDeleteUsersResult.getUsersToDelete());
                return ResponseEntity.ok(Map.of("message", "Users deleted successfully"));
            }
            return ResponseEntity.ok(Map.of("message", "No users to delete"));
        }
        return ResponseEntity.badRequest().body(validateInputsForDeleteUsersResult.getMapOfErrors());
    }

    private ValidateInputsForDeleteUsersResultDto validateInputsForDeleteUsers(Set<String> usernamesOrEmails, UserDetailsImpl deleter, String deleterHighestTopRole, boolean hardDelete) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        Variant variant = unleash.getVariant(ALLOW_DELETE_USERS.name());
        if (entryCheck(variant, deleterHighestTopRole)) {
            checkUserCanDeleteUsers(deleterHighestTopRole);
            validateInputsSizeForUsersDeletion(variant, usernamesOrEmails);
            ValidateInputsForDeleteOrReadUsersResultDto validateInputsForDeleteOrReadUsersResult = validateInputsForDeleteOrReadUsers(usernamesOrEmails, deleter);
            Map<String, Object> mapOfErrors = new HashMap<>();
            if (!validateInputsForDeleteOrReadUsersResult.getInvalidInputs().isEmpty()) {
                mapOfErrors.put("invalid_inputs", validateInputsForDeleteOrReadUsersResult.getInvalidInputs());
            }
            if (!validateInputsForDeleteOrReadUsersResult.getOwnUserInInputs().isEmpty()) {
                mapOfErrors.put("you_cannot_delete_your_own_account_using_this_endpoint", validateInputsForDeleteOrReadUsersResult.getOwnUserInInputs());
            }
            if (!mapOfErrors.isEmpty()) {
                return new ValidateInputsForDeleteUsersResultDto(mapOfErrors, null);
            }
            return getUsersDeletionResult(validateInputsForDeleteOrReadUsersResult, deleter, deleterHighestTopRole, hardDelete);
        }
        throw new ServiceUnavailableException("Deletion of users is currently disabled. Please try again later");
    }

    private void checkUserCanDeleteUsers(String deleterHighestTopRole) {
        if (deleterHighestTopRole == null && !unleash.isEnabled(ALLOW_DELETE_USERS_BY_USERS_HAVE_PERMISSION_TO_DELETE_USERS.name())) {
            throw new ServiceUnavailableException("Deletion of users is currently disabled. Please try again later");
        }
    }

    private void validateInputsSizeForUsersDeletion(Variant variant, Set<String> usernamesOrEmails) {
        if (usernamesOrEmails.isEmpty()) {
            throw new SimpleBadRequestException("No users to delete");
        }
        if (variant.isEnabled() && variant.getPayload().isPresent()) {
            int maxUsersToDeleteAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
            if (maxUsersToDeleteAtATime < 1) {
                maxUsersToDeleteAtATime = DEFAULT_MAX_USERS_TO_DELETE_AT_A_TIME;
            }
            if (usernamesOrEmails.size() > maxUsersToDeleteAtATime) {
                throw new SimpleBadRequestException("Cannot delete more than " + maxUsersToDeleteAtATime + " users at a time");
            }
        } else if (usernamesOrEmails.size() > DEFAULT_MAX_USERS_TO_DELETE_AT_A_TIME) {
            throw new SimpleBadRequestException("Cannot delete more than " + DEFAULT_MAX_USERS_TO_DELETE_AT_A_TIME + " users at a time");
        }
    }

    private ValidateInputsForDeleteOrReadUsersResultDto validateInputsForDeleteOrReadUsers(Set<String> usernamesOrEmails, UserDetailsImpl user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        Set<String> invalidInputs = new HashSet<>();
        Set<String> emails = new HashSet<>();
        Set<String> usernames = new HashSet<>();
        Set<String> ownUserInInputs = new HashSet<>();
        usernamesOrEmails.remove(null);
        for (String identifier : usernamesOrEmails) {
            if (USERNAME_PATTERN.matcher(identifier).matches()) {
                usernames.add(identifier);
            } else if (EMAIL_PATTERN.matcher(identifier).matches()) {
                emails.add(identifier);
            } else {
                invalidInputs.add(identifier);
            }
        }
        String ownUsername = genericAesStaticEncryptorDecryptor.decrypt(user.getUsername(), String.class);
        if (usernames.contains(ownUsername)) {
            ownUserInInputs.add(ownUsername);
        }
        String ownEmail = genericAesStaticEncryptorDecryptor.decrypt(user.getUser().getEmail(), String.class);
        if (emails.contains(ownEmail)) {
            ownUserInInputs.add(ownEmail);
        }
        return new ValidateInputsForDeleteOrReadUsersResultDto(invalidInputs, usernames, emails, ownUserInInputs);
    }

    private ValidateInputsForDeleteUsersResultDto getUsersDeletionResult(ValidateInputsForDeleteOrReadUsersResultDto validateInputsForDeleteOrReadUsersResult, UserDetailsImpl deleter, String deleterHighestTopRole, boolean hardDelete) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        Set<String> tempSet = new HashSet<>();
        Map<String, String> tempMap = new HashMap<>();
        String tempStr;
        for (String username : validateInputsForDeleteOrReadUsersResult.getUsernames()) {
            tempStr = genericAesStaticEncryptorDecryptor.encrypt(username);
            tempSet.add(tempStr);
            tempMap.put(tempStr, username);
        }
        Set<UserModel> usersToDelete = new HashSet<>();
        Set<String> restrictedRoles = new HashSet<>();
        for (UserModel userModel : userRepo.findByUsernameIn(tempSet)) {
            validateInputsForDeleteOrReadUsersResult.getUsernames().remove(tempMap.get(userModel.getUsername()));
            userDeletionResult(userModel, deleter, deleterHighestTopRole, restrictedRoles, usersToDelete, hardDelete);
        }
        tempSet.clear();
        tempMap.clear();
        for (String email : validateInputsForDeleteOrReadUsersResult.getEmails()) {
            tempStr = genericAesStaticEncryptorDecryptor.encrypt(email);
            tempSet.add(tempStr);
            tempMap.put(tempStr, email);
        }
        for (UserModel userModel : userRepo.findByEmailIn(tempSet)) {
            validateInputsForDeleteOrReadUsersResult.getEmails().remove(tempMap.get(userModel.getEmail()));
            userDeletionResult(userModel, deleter, deleterHighestTopRole, restrictedRoles, usersToDelete, hardDelete);
        }
        Map<String, Object> mapOfErrors = new HashMap<>();
        if (!validateInputsForDeleteOrReadUsersResult.getUsernames().isEmpty()) {
            mapOfErrors.put("users_not_found_with_usernames", validateInputsForDeleteOrReadUsersResult.getUsernames());
        }
        if (!validateInputsForDeleteOrReadUsersResult.getEmails().isEmpty()) {
            mapOfErrors.put("users_not_found_with_emails", validateInputsForDeleteOrReadUsersResult.getEmails());
        }
        if (!restrictedRoles.isEmpty()) {
            mapOfErrors.put("not_allowed_to_delete_users_having_roles", restrictedRoles);
        }
        return new ValidateInputsForDeleteUsersResultDto(mapOfErrors, usersToDelete);
    }

    private void userDeletionResult(UserModel userModel, UserDetailsImpl deleter, String deleterHighestTopRole, Set<String> restrictedRoles, Set<UserModel> usersToDelete, boolean hardDelete) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (hardDelete) {
            boolean tempBoolean = validateRoleRestriction(userModel, deleterHighestTopRole, restrictedRoles);
            if (tempBoolean) {
                usersToDelete.add(userModel);
            }
        } else {
            if (!userModel.isAccountDeleted()) {
                boolean tempBoolean = validateRoleRestriction(userModel, deleterHighestTopRole, restrictedRoles);
                if (tempBoolean) {
                    userModel.recordAccountDeletionStatus(true, genericAesRandomEncryptorDecryptor.encrypt(deleter.getUsername()));
                    usersToDelete.add(userModel);
                }
            }
        }
    }

    private boolean validateRoleRestriction(UserModel user, String userHighestTopRole, Set<String> restrictedRoles) {
        boolean collectUser = true;
        if (user.getRoles() != null && !user.getRoles().isEmpty()) {
            for (RoleModel role : user.getRoles()) {
                if (!TOP_ROLES.getFirst().equals(userHighestTopRole)) {
                    if (ROLE_PRIORITY_MAP.containsKey(role.getRoleName())) {
                        if (userHighestTopRole == null || ROLE_PRIORITY_MAP.get(role.getRoleName()) <= ROLE_PRIORITY_MAP.get(userHighestTopRole)) {
                            restrictedRoles.add(role.getRoleName());
                            collectUser = false;
                        }
                    }
                }
            }
        }
        return collectUser;
    }

    public ResponseEntity<Map<String, Object>> deleteUsersLenient(Set<String> usernamesOrEmails) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserDetailsImpl deleter = getCurrentAuthenticatedUserDetails();
        String deleterHighestTopRole = getUserHighestTopRole(deleter);
        ValidateInputsForDeleteUsersResultDto validateInputsForDeleteUsersResult = validateInputsForDeleteUsers(usernamesOrEmails, deleter, deleterHighestTopRole, false);
        if (!validateInputsForDeleteUsersResult.getUsersToDelete().isEmpty()) {
            accessTokenUtility.revokeTokens(validateInputsForDeleteUsersResult.getUsersToDelete());
            userRepo.saveAll(validateInputsForDeleteUsersResult.getUsersToDelete());
            return ResponseEntity.ok(Map.of("message", "Users deleted successfully"));
        }
        return ResponseEntity.ok(Map.of("message", "No users to delete"));
    }

    public ResponseEntity<Map<String, Object>> deleteUsersHard(Set<String> usernamesOrEmails) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserDetailsImpl user = getCurrentAuthenticatedUserDetails();
        String userHighestTopRole = getUserHighestTopRole(user);
        if (unleash.isEnabled(ALLOW_HARD_DELETE_USERS.name()) || TOP_ROLES.getFirst().equals(userHighestTopRole)) {
            checkUserCanHardDeleteUsers(userHighestTopRole);
            ValidateInputsForDeleteUsersResultDto validateInputsForDeleteUsersResult = validateInputsForDeleteUsers(usernamesOrEmails, user, userHighestTopRole, true);
            if (validateInputsForDeleteUsersResult.getMapOfErrors().isEmpty()) {
                if (!validateInputsForDeleteUsersResult.getUsersToDelete().isEmpty()) {
                    accessTokenUtility.revokeTokens(validateInputsForDeleteUsersResult.getUsersToDelete());
                    userRepo.deleteAll(validateInputsForDeleteUsersResult.getUsersToDelete());
                    return ResponseEntity.ok(Map.of("message", "Users deleted successfully"));
                }
                return ResponseEntity.ok(Map.of("message", "No users to delete"));
            }
            return ResponseEntity.badRequest().body(validateInputsForDeleteUsersResult.getMapOfErrors());
        }
        throw new ServiceUnavailableException("Hard deletion of users is currently disabled. Please try again later");
    }

    private void checkUserCanHardDeleteUsers(String userHighestTopRole) {
        if (userHighestTopRole == null && !unleash.isEnabled(ALLOW_HARD_DELETE_USERS_BY_USERS_HAVE_PERMISSION_TO_DELETE_USERS.name())) {
            throw new ServiceUnavailableException("Hard deletion of users is currently disabled. Please try again later");
        }
    }

    public ResponseEntity<Map<String, Object>> deleteUsersHardLenient(Set<String> usernamesOrEmails) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserDetailsImpl user = getCurrentAuthenticatedUserDetails();
        String userHighestTopRole = getUserHighestTopRole(user);
        if (unleash.isEnabled(ALLOW_HARD_DELETE_USERS.name()) || TOP_ROLES.getFirst().equals(userHighestTopRole)) {
            checkUserCanHardDeleteUsers(userHighestTopRole);
            ValidateInputsForDeleteUsersResultDto validateInputsForDeleteUsersResult = validateInputsForDeleteUsers(usernamesOrEmails, user, userHighestTopRole, true);
            if (!validateInputsForDeleteUsersResult.getUsersToDelete().isEmpty()) {
                accessTokenUtility.revokeTokens(validateInputsForDeleteUsersResult.getUsersToDelete());
                userRepo.deleteAll(validateInputsForDeleteUsersResult.getUsersToDelete());
                return ResponseEntity.ok(Map.of("message", "Users deleted successfully"));
            }
            return ResponseEntity.ok(Map.of("message", "No users to delete"));
        }
        throw new ServiceUnavailableException("Hard deletion of users is currently disabled. Please try again later");
    }
}
