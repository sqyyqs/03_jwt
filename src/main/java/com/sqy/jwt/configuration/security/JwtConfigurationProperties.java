package com.sqy.jwt.configuration.security;

import java.util.*;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "spring.security.oauth2.resourceserver.jwt")
public class JwtConfigurationProperties {
    public static final List<String> REFRESH_TOKEN_AUTHORITIES = List.of("REFRESH", "LOGOUT");

    private String authoritiesClaimName;
    private String encAlgorithm;
    private String jwsAlgorithms;

    public String getAuthoritiesClaimName() {
        return authoritiesClaimName;
    }

    public void setAuthoritiesClaimName(String authoritiesClaimName) {
        this.authoritiesClaimName = authoritiesClaimName;
    }

    public String getEncAlgorithm() {
        return encAlgorithm;
    }

    public void setEncAlgorithm(String encAlgorithm) {
        this.encAlgorithm = encAlgorithm;
    }

    public String getJwsAlgorithms() {
        return jwsAlgorithms;
    }

    public void setJwsAlgorithms(String jwsAlgorithms) {
        this.jwsAlgorithms = jwsAlgorithms;
    }
}
