package org.vimal.security.v3.utils;

public final class MailTemplateUtility {
    private MailTemplateUtility() {
    }

    public static final String OTP_TEMPLATE = """
            Your verification otp is: %s
            This otp will expire in 5 minutes.
            """;
    public static final String LINK_TEMPLATE = """
            Your verification link is: %s
            This link will expire in 5 minutes.
            """;
    public static final String ACCOUNT_DELETION_CONFIRMATION_TEMPLATE = """
            Your account has been deleted successfully & will be completely removed from backup after 30 days.
            If this was a mistake or you want to recover your account or not done by you or if you want to remove your account from backup immediately, please contact support.
            """;
    public static final String PASSWORD_RESET_CONFIRMATION_TEMPLATE = """
            Your password has been reset successfully.
            If this was not done by you, please contact support immediately.
            """;
    public static final String SELF_PASSWORD_CHANGE_CONFIRMATION_TEMPLATE = """
            Your password has been changed successfully.
            If this was not done by you, please contact support immediately.
            """;
    public static final String SELF_EMAIL_CHANGE_CONFIRMATION_TEMPLATE = """
            Your email has been changed successfully.
            If this was not done by you, please contact support immediately.
            """;
    public static final String SELF_UPDATE_DETAILS_CONFIRMATION_TEMPLATE = """
            Your details have been updated successfully.
            If this was not done by you, please contact support immediately.
            """;
    public static final String SELF_MFA_ENABLE_DISABLE_CONFIRMATION_TEMPLATE = """
            %s.
            If this was not done by you, please contact support immediately.
            """;
}
