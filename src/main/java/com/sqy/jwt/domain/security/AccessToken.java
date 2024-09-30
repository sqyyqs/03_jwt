package com.sqy.jwt.domain.security;

import java.time.Instant;

public record AccessToken(
    String tokenValue,
    Instant tokenExpiry
) {
}
