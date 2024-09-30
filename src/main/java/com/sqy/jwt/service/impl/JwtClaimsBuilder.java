package com.sqy.jwt.service.impl;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

import com.nimbusds.jose.HeaderParameterNames;
import com.sqy.jwt.configuration.security.JwtConfigurationProperties;
import com.sqy.jwt.dto.UserDto;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

@Component
public class JwtClaimsBuilder {
    private static final int REFRESH_TOKEN_TTL_MINUTES = 15 * 24 * 60;
    private static final int ACCESS_TOKEN_TTL_MINUTES = 5;

    private final JwtConfigurationProperties jwtConfigurationProperties;

    public JwtClaimsBuilder(JwtConfigurationProperties jwtConfigurationProperties) {
        this.jwtConfigurationProperties = jwtConfigurationProperties;
    }

    public JwtEncoderParameters params(UserDto userDto, boolean isRefresh) {
        List<String> authorities;
        int tokenTTL;

        if (isRefresh) {
            authorities = JwtConfigurationProperties.REFRESH_TOKEN_AUTHORITIES;
            tokenTTL = REFRESH_TOKEN_TTL_MINUTES;
        } else {
            authorities = userDto.roles();
            tokenTTL = ACCESS_TOKEN_TTL_MINUTES;
        }

        return JwtEncoderParameters.from(
            JwsHeader.with(SignatureAlgorithm.from(jwtConfigurationProperties.getJwsAlgorithms()))
                .header(HeaderParameterNames.ENCRYPTION_ALGORITHM, jwtConfigurationProperties.getEncAlgorithm())
                .build(),
            JwtClaimsSet.builder()
                .expiresAt(Instant.now().plus(Duration.ofMinutes(tokenTTL)))
                .issuedAt(Instant.now())
                .subject(userDto.username())
                .claim(jwtConfigurationProperties.getAuthoritiesClaimName(), authorities)
                .build()
        );
    }
}
