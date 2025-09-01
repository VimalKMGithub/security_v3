package org.vimal.security.v3.configs;

import io.getunleash.DefaultUnleash;
import io.getunleash.Unleash;
import io.getunleash.util.UnleashConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class UnleashServerConfig {
    private static final String UNLEASH_APP_NAME = "SECURITY_V3";
    private static final String UNLEASH_INSTANCE_ID = "SECURITY_V3_INSTANCE_1";
    private final PropertiesConfig propertiesConfig;

    @Bean
    public Unleash unleash() {
        return new DefaultUnleash(UnleashConfig.builder()
                .appName(UNLEASH_APP_NAME)
                .instanceId(UNLEASH_INSTANCE_ID)
                .unleashAPI(propertiesConfig.getUnleashUrl())
                .synchronousFetchOnInitialisation(true)
                .apiKey(propertiesConfig.getUnleashApiToken())
                .fetchTogglesInterval(5)
                .build());
    }
}
