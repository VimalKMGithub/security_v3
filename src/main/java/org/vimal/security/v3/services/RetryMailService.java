package org.vimal.security.v3.services;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Recover;
import org.springframework.retry.annotation.Retryable;
import org.springframework.stereotype.Service;
import org.vimal.security.v3.configs.PropertiesConfig;

@Slf4j
@Service
@RequiredArgsConstructor
public class RetryMailService {
    private final JavaMailSender mailSender;
    private final PropertiesConfig propertiesConfig;

    @Retryable(
            retryFor = Exception.class,
            maxAttempts = 5,
            backoff = @Backoff(
                    delay = 5000,
                    multiplier = 2.0
            )
    )
    public void sendEmail(String to,
                          String subject,
                          String text) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(String.format(
                        "%s <%s>",
                        propertiesConfig.getMailDisplayName(),
                        "takenCareAuto"
                )
        );
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text + getSignature());
        mailSender.send(message);
    }

    @Recover
    public void logIfSendEmailFails(Exception ex,
                                    String to,
                                    String subject,
                                    String text) {
        log.error(
                "Failed to send email to '{}' with subject '{}'. Error: {}",
                to,
                subject,
                ex.getMessage()
        );
    }

    private String getSignature() {
        return String.format("""
                        \n
                        -------------------------------
                        Best regards,
                        -------------------------------
                        This email was sent from the %s.
                        If you have any queries, please contact us at %s
                        """,
                propertiesConfig.getMailDisplayName(),
                propertiesConfig.getHelpMailAddress()
        );
    }
}
