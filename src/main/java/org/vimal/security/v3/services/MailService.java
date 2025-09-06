package org.vimal.security.v3.services;

import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.vimal.security.v3.enums.MailType;

import static org.vimal.security.v3.utils.MailTemplateUtility.*;

@Service
@RequiredArgsConstructor
public class MailService {
    private final RetryMailService retryMailService;

    private void sendEmail(String to,
                           String subject,
                           String text) {
        retryMailService.sendEmail(
                to,
                subject,
                text
        );
    }

    private void sendEmail(String to,
                           String subject,
                           String value,
                           MailType mailType) {
        String text = switch (mailType) {
            case OTP -> String.format(
                    OTP_TEMPLATE,
                    value
            );
            case LINK -> String.format(
                    LINK_TEMPLATE,
                    value
            );
            case ACCOUNT_DELETION_CONFIRMATION -> ACCOUNT_DELETION_CONFIRMATION_TEMPLATE;
            case PASSWORD_RESET_CONFIRMATION -> PASSWORD_RESET_CONFIRMATION_TEMPLATE;
            case SELF_PASSWORD_CHANGE_CONFIRMATION -> SELF_PASSWORD_CHANGE_CONFIRMATION_TEMPLATE;
            case SELF_EMAIL_CHANGE_CONFIRMATION -> SELF_EMAIL_CHANGE_CONFIRMATION_TEMPLATE;
            case SELF_UPDATE_DETAILS_CONFIRMATION -> SELF_UPDATE_DETAILS_CONFIRMATION_TEMPLATE;
            case SELF_MFA_ENABLE_DISABLE_CONFIRMATION -> String.format(
                    SELF_MFA_ENABLE_DISABLE_CONFIRMATION_TEMPLATE,
                    value
            );
        };
        sendEmail(
                to,
                subject,
                text
        );
    }

    @Async
    public void sendEmailAsync(String to,
                               String subject,
                               String value,
                               MailType mailType) {
        sendEmail(
                to,
                subject,
                value,
                mailType
        );
    }
}
