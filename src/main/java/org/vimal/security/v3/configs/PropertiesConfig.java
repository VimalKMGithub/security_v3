package org.vimal.security.v3.configs;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "properties")
public class PropertiesConfig {
    private String genericAesRandomSecretKey;
    private String genericAesStaticSecretKey;
    private String unleashUrl;
    private String unleashApiToken;
    private String accessTokenSigningSecretKey;
    private String accessTokenEncryptionSecretKey;
    private String mailDisplayName;
    private String helpMailAddress;
    private String godUserUsername;
    private String globalAdminUserUsername;
    private String godUserEmail;
    private String globalAdminUserEmail;
    private String godUserPassword;
    private String globalAdminUserPassword;
}
