package com.sqy.jwt.repository;

import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class RoleRepository {
    private static final Logger logger = LoggerFactory.getLogger(RoleRepository.class);
    private static final String SQL_INSERT_ROLES_BASE = """
        INSERT INTO user_roles
        VALUES """;
    private static final String SQL_SELECT_ROLES_BY_USERNAME = """
        SELECT role_name
        FROM user_roles
        WHERE user_id IN (SELECT user_id
                          FROM jwt_user
                          WHERE username = :username)
        """;
    private final NamedParameterJdbcTemplate npjdbc;

    public RoleRepository(NamedParameterJdbcTemplate npjdbc) { this.npjdbc = npjdbc; }

    public void saveRoles(List<String> roles, Long userId) {
        String sql = buildInsertSql(roles);
        MapSqlParameterSource parameters = buildParameterSource(roles, userId);

        npjdbc.update(sql, parameters);
    }

    public List<String> findRolesByLogin(String username) {
        try {
            return npjdbc.queryForList(SQL_SELECT_ROLES_BY_USERNAME, new MapSqlParameterSource("username", username), String.class);
        } catch (DataAccessException e) {
            logger.warn("Invoke findRolesByLogin({}) with exception.", username, e);
        }
        return null;
    }

    private static String buildInsertSql(List<String> roles) {
        StringBuilder sqlBuilder = new StringBuilder(SQL_INSERT_ROLES_BASE);
        for (int i = 0; i < roles.size(); i++) {
            sqlBuilder.append("(:user_id").append(", :role_name").append(i).append("),");
        }
        return sqlBuilder.substring(0, sqlBuilder.length() - 1);
    }

    private static MapSqlParameterSource buildParameterSource(List<String> roles, long userId) {
        MapSqlParameterSource mapSqlParameterSource = new MapSqlParameterSource("user_id", userId);
        for (int i = 0; i < roles.size(); i++) {
            mapSqlParameterSource.addValue("role_name" + i, roles.get(i));
        }
        return mapSqlParameterSource;
    }
}
