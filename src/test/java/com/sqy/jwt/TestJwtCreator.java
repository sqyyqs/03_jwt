package com.sqy.jwt;

import com.sqy.jwt.domain.security.AccessToken;
import com.sqy.jwt.domain.security.JwtAuthenticationResponseTokens;
import com.sqy.jwt.domain.security.RefreshToken;
import com.sqy.jwt.dto.UserDto;
import com.sqy.jwt.service.impl.JwtClaimsBuilder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

@Component
public class TestJwtCreator {
    private final JwtEncoder jwtEncoder;
    private final JwtClaimsBuilder jwtClaimsBuilder;

    public TestJwtCreator(JwtEncoder jwtEncoder, JwtClaimsBuilder jwtClaimsBuilder) {
        this.jwtEncoder = jwtEncoder;
        this.jwtClaimsBuilder = jwtClaimsBuilder;
    }

    public String accessToken(UserDto userDto) {
        JwtEncoderParameters accessTokenParams = jwtClaimsBuilder.params(userDto, false);
        return jwtEncoder.encode(accessTokenParams).getTokenValue();
    }

    public String refreshToken(UserDto userDto) {
        JwtEncoderParameters refreshTokenParams = jwtClaimsBuilder.params(userDto, true);
        return jwtEncoder.encode(refreshTokenParams).getTokenValue();
    }

    public AccessToken accessTokenEntity(UserDto userDto) {
        JwtEncoderParameters accessTokenParams = jwtClaimsBuilder.params(userDto, false);
        Jwt accessToken = jwtEncoder.encode(accessTokenParams);
        return new AccessToken(accessToken.getTokenValue(), accessToken.getExpiresAt());
    }

    public RefreshToken refreshTokenEntity(UserDto userDto) {
        JwtEncoderParameters refreshTokenParams = jwtClaimsBuilder.params(userDto, true);
        Jwt refreshToken = jwtEncoder.encode(refreshTokenParams);
        return new RefreshToken(refreshToken.getTokenValue(), refreshToken.getExpiresAt());
    }

    public JwtAuthenticationResponseTokens tokens(UserDto userDto) {
        Jwt access = jwtEncoder.encode(jwtClaimsBuilder.params(userDto, false));
        Jwt refresh = jwtEncoder.encode(jwtClaimsBuilder.params(userDto, true));
        return new JwtAuthenticationResponseTokens(
            new AccessToken(access.getTokenValue(), access.getExpiresAt()),
            new RefreshToken(refresh.getTokenValue(), refresh.getExpiresAt())
        );
    }
}

