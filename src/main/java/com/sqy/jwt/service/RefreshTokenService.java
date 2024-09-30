package com.sqy.jwt.service;

import com.sqy.jwt.domain.security.RefreshToken;

public interface RefreshTokenService {
    void save(RefreshToken refreshToken);
    boolean isRevoked(RefreshToken refreshToken);
}
