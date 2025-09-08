package org.vimal.security.v3.configs;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.vimal.security.v3.filters.AccessTokenFilter;
import org.vimal.security.v3.filters.ServerUpFilter;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private static final String API_VERSION = "/api/v1";
    private static final String USER = "/user";
    private static final String AUTH = "/auth";
    private static final String MFA = "/mfa";
    private static final String[] ALLOWED_API_ENDPOINT_WITHOUT_AUTHENTICATION = {
            API_VERSION + AUTH + "/login",
            API_VERSION + AUTH + "/refresh/accessToken",
            API_VERSION + AUTH + "/revoke/refreshToken",
            API_VERSION + AUTH + MFA + "/requestTo/login",
            API_VERSION + AUTH + MFA + "/verifyTo/login",
            API_VERSION + USER + "/register",
            API_VERSION + USER + "/verifyEmail",
            API_VERSION + USER + "/resend/emailVerification/link",
            API_VERSION + USER + "/forgot/password",
            API_VERSION + USER + "/forgot/password/methodSelection",
            API_VERSION + USER + "/reset/password"
    };
    private final AccessTokenFilter accessTokenFilter;
    private final ServerUpFilter serverUpFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.cors(cors -> cors
                        .configurationSource(corsConfigurationSource())
                )
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(
                        auth -> auth
                                .requestMatchers(ALLOWED_API_ENDPOINT_WITHOUT_AUTHENTICATION)
                                .permitAll()
                                .anyRequest()
                                .authenticated()
                )
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'")
                        )
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .preload(true)
                                .maxAgeInSeconds(63072000)
                        )
                        .xssProtection(xss -> xss
                                .headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)
                        )
                        .referrerPolicy(referrer -> referrer
                                .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                        )
                )
                .addFilterBefore(
                        serverUpFilter,
                        UsernamePasswordAuthenticationFilter.class
                )
                .addFilterBefore(
                        accessTokenFilter,
                        UsernamePasswordAuthenticationFilter.class
                );
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http,
                                                       PasswordEncoder passwordEncoder,
                                                       UserDetailsService userDetailsService) throws Exception {
        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        builder.userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);
        return builder.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Argon2PasswordEncoder(
                16,
                32,
                2,
                65536,
                3
        );
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(List.of("http://localhost:*"));
        configuration.setAllowedMethods(List.of(
                        "GET",
                        "POST",
                        "PUT",
                        "DELETE"
                )
        );
        configuration.setAllowedHeaders(List.of(
                        "Authorization",
                        "Content-Type",
                        "Accept",
                        "Origin",
                        "X-Requested-With",
                        "X-XSRF-TOKEN",
                        "If-Modified-Since",
                        "Cache-Control"
                )
        );
        configuration.setExposedHeaders(List.of(
                        "Content-Disposition",
                        "X-XSRF-TOKEN",
                        "Authorization",
                        "X-Total-Count",
                        "Location"
                )
        );
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration(
                "/**",
                configuration
        );
        return source;
    }
}
