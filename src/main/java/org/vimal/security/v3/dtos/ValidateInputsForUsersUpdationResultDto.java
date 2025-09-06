package org.vimal.security.v3.dtos;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Map;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
public class ValidateInputsForUsersUpdationResultDto extends ValidateInputsForUsersCreationResultDto {
    private Set<String> encryptedOldUsernames;
    private Map<String, String> encryptedOldUsernameToOldUsernameMap;
    private Map<String, String> oldUsernameToEncryptedOldUsernameMap;
    private Set<String> duplicateOldUsernames;
    private Set<String> invalidOldUsernames;
    private Map<String, String> encryptedUsernameToEncryptedOldUsernameMap;
    private Map<String, String> encryptedEmailToEncryptedOldUsernameMap;

    public ValidateInputsForUsersUpdationResultDto(Set<String> invalidInputs,
                                                   Set<String> encryptedUsernames,
                                                   Map<String, String> encryptedUsernameToUsernameMap,
                                                   Map<String, String> usernameToEncryptedUsernameMap,
                                                   Set<String> encryptedEmails,
                                                   Map<String, String> encryptedEmailToEmailMap,
                                                   Map<String, String> emailToEncryptedEmailMap,
                                                   Set<String> duplicateUsernamesInDtos,
                                                   Set<String> duplicateEmailsInDtos,
                                                   Set<String> roles,
                                                   Set<String> restrictedRoles,
                                                   Set<String> encryptedOldUsernames,
                                                   Map<String, String> encryptedOldUsernameToOldUsernameMap,
                                                   Map<String, String> oldUsernameToEncryptedOldUsernameMap,
                                                   Set<String> duplicateOldUsernames,
                                                   Set<String> invalidOldUsernames,
                                                   Map<String, String> encryptedUsernameToEncryptedOldUsernameMap,
                                                   Map<String, String> encryptedEmailToEncryptedOldUsernameMap) {
        super(
                invalidInputs,
                encryptedUsernames,
                encryptedUsernameToUsernameMap,
                usernameToEncryptedUsernameMap,
                encryptedEmails,
                encryptedEmailToEmailMap,
                emailToEncryptedEmailMap,
                duplicateUsernamesInDtos,
                duplicateEmailsInDtos,
                roles,
                restrictedRoles
        );
        this.encryptedOldUsernames = encryptedOldUsernames;
        this.encryptedOldUsernameToOldUsernameMap = encryptedOldUsernameToOldUsernameMap;
        this.oldUsernameToEncryptedOldUsernameMap = oldUsernameToEncryptedOldUsernameMap;
        this.duplicateOldUsernames = duplicateOldUsernames;
        this.invalidOldUsernames = invalidOldUsernames;
        this.encryptedUsernameToEncryptedOldUsernameMap = encryptedUsernameToEncryptedOldUsernameMap;
        this.encryptedEmailToEncryptedOldUsernameMap = encryptedEmailToEncryptedOldUsernameMap;
    }
}
