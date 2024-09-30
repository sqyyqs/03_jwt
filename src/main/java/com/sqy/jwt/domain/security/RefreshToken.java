package com.sqy.jwt.domain.security;

import java.time.Instant;

public record RefreshToken(
    String tokenValue,
    Instant tokenExpiry
) {
}
