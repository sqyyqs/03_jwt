package com.sqy.jwt.domain.security;

public record JwtAuthenticationResponseTokens(
    AccessToken accessToken,
    RefreshToken refreshToken
) {
}
