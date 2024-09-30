package com.sqy.jwt;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

import com.sqy.jwt.dto.UserDto;
import com.sqy.jwt.service.impl.JwtClaimsBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

@SpringBootTest
public class TestJwtEncodingDecoding {
    @Autowired
    private JwtEncoder jwtEncoder;
    @Autowired
    private JwtDecoder jwtDecoder;
    @Autowired
    private JwtClaimsBuilder jwtClaimsBuilder;

    @Test
    void testAuthorities() {
        List<String> mockUserAuthorities = List.of("COOL", "GUY");

        UserDto userDto = new UserDto("some_username", mockUserAuthorities);
        JwtEncoderParameters accessParams = jwtClaimsBuilder.params(userDto, false);
        JwtEncoderParameters refreshParams = jwtClaimsBuilder.params(userDto, true);

        Jwt accessToken = jwtEncoder.encode(accessParams);
        Jwt refreshToken = jwtEncoder.encode(refreshParams);

        Assertions.assertEquals(mockUserAuthorities, accessToken.getClaimAsStringList("authorities"));
        Assertions.assertEquals(refreshToken.getClaimAsStringList("authorities"), (List.of("REFRESH", "LOGOUT")));

        //access token TTL < 1 day
        Assertions.assertTrue(accessToken.getExpiresAt().isBefore(Instant.now().plus(Duration.ofDays(1))));
        //refresh token TTL > week
        Assertions.assertTrue(refreshToken.getExpiresAt().isAfter(Instant.now().plus(Duration.ofDays(7))));
    }


    @Test
    void testDecoding() {
        List<String> mockUserAuthorities = List.of("COOL", "GUY");

        UserDto userDto = new UserDto("some_username", mockUserAuthorities);
        JwtEncoderParameters accessParams = jwtClaimsBuilder.params(userDto, false);
        JwtEncoderParameters refreshParams = jwtClaimsBuilder.params(userDto, true);

        Jwt accessToken = jwtEncoder.encode(accessParams);
        Jwt refreshToken = jwtEncoder.encode(refreshParams);

        Jwt decodedAccessToken = jwtDecoder.decode(accessToken.getTokenValue());
        Jwt decodedRefreshToken = jwtDecoder.decode(refreshToken.getTokenValue());

        Assertions.assertEquals(accessToken.getSubject(), decodedAccessToken.getSubject());
        Assertions.assertEquals(refreshToken.getSubject(), refreshToken.getSubject());
    }
}
