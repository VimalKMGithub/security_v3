package org.vimal.security.v3.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AlreadyTakenUsernamesAndEmailsResultDto {
    private Set<String> alreadyTakenUsernames;
    private Set<String> alreadyTakenEmails;
}
