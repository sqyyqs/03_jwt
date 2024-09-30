package com.sqy.jwt.repository;

import java.util.*;

import com.sqy.jwt.domain.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository {
    private static final Logger logger = LoggerFactory.getLogger(UserRepository.class);
    private static final String SQL_SELECT_BY_USERNAME = """
        SELECT jwt_user.user_id, username, password, role_name
        FROM jwt_user
             JOIN user_roles ur on jwt_user.user_id = ur.user_id
         WHERE username = :username;
        """;
    private static final String SQL_INSERT_USER = """
        INSERT INTO jwt_user
        VALUES (default, :username, :password);
        """;
    private final NamedParameterJdbcTemplate npjdbc;

    public UserRepository(NamedParameterJdbcTemplate npjdbc) {
        this.npjdbc = npjdbc;
    }

    public User findByUsername(String username) {
        try {
            return npjdbc.query(SQL_SELECT_BY_USERNAME,
                new MapSqlParameterSource("username", username),
                rs -> {
                    rs.next();
                    User userEntity = new User(rs.getLong("user_id"), rs.getString("username"), rs.getString("password"), new ArrayList<>());
                    do {
                        userEntity.roles().add(rs.getString("role_name"));
                    } while (rs.next());
                    return userEntity;
                }
            );
        } catch (DataAccessException e) {
            logger.warn("Invoke findByCredentials with exception.", e);
        }
        return null;
    }

    public Long createUser(User user) {
        try {
            GeneratedKeyHolder idKeyHolder = new GeneratedKeyHolder();
            npjdbc.update(SQL_INSERT_USER,
                credentialsParameterSource(user.username(), user.encodedPassword()), idKeyHolder, new String[] { "user_id" });
            return (Long) idKeyHolder.getKey();
        } catch (DataAccessException e) {
            logger.warn("Invoke createUser with exception.", e);
        }
        return null;
    }

    private static MapSqlParameterSource credentialsParameterSource(String username, String password) {
        return new MapSqlParameterSource("username", username).addValue("password", password);
    }
}
