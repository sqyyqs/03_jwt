package com.sqy.jwt.repository;

import java.sql.Timestamp;
import java.sql.Types;

import com.sqy.jwt.domain.security.RefreshToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class RefreshTokenRepository {
    private static final String SQL_INSERT_TOKEN = """
        INSERT INTO revoked_token
        VALUES(:token_value, :expiry)""";
    private static final String SQL_EXISTS_BY_ID = """
        SELECT EXISTS(SELECT 1
                      FROM revoked_token
                      WHERE token_value = :token_value)
        """;
    private static final Logger log = LoggerFactory.getLogger(RefreshTokenRepository.class);
    private final NamedParameterJdbcTemplate npjdbc;

    public RefreshTokenRepository(NamedParameterJdbcTemplate namedParameterJdbcTemplate) {
        this.npjdbc = namedParameterJdbcTemplate;
    }

    public void save(RefreshToken refreshToken) {
        try {
            MapSqlParameterSource tokenParamsSource = new MapSqlParameterSource("token_value", refreshToken.tokenValue())
                .addValue("expiry", Timestamp.from(refreshToken.tokenExpiry()), Types.TIMESTAMP);
            npjdbc.update(SQL_INSERT_TOKEN, tokenParamsSource);
        } catch (DataAccessException e) {
            log.info("Invoke save() with exception.", e);
        }
    }

    public boolean existsByValue(String tokenValue) {
        try {
            return Boolean.TRUE.equals(npjdbc.queryForObject(
                SQL_EXISTS_BY_ID,
                new MapSqlParameterSource("token_value", tokenValue),
                Boolean.class)
            );
        } catch (DataAccessException e) {
            log.info("Invoke existsByValue() with exception.", e);
        }
        return false;
    }
}
