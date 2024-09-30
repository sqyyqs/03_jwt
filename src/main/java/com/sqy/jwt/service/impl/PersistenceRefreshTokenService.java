package com.sqy.jwt.service.impl;

import com.sqy.jwt.domain.security.RefreshToken;
import com.sqy.jwt.repository.RefreshTokenRepository;
import com.sqy.jwt.service.RefreshTokenService;
import org.springframework.stereotype.Service;

@Service
public class PersistenceRefreshTokenService implements RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;

    public PersistenceRefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Override
    public void save(RefreshToken refreshToken) {
        refreshTokenRepository.save(refreshToken);
    }

    @Override
    public boolean isRevoked(RefreshToken refreshToken) {
        return refreshTokenRepository.existsByValue(refreshToken.tokenValue());
    }
}
