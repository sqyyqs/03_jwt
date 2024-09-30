package com.sqy.jwt.domain.security;

public record AuthenticationRequest(
    String login,
    String password
) {
}