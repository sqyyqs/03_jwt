package com.sqy.jwt.configuration;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

@Configuration
public class DataAccessConfiguration {
    @Bean
    public NamedParameterJdbcTemplate npjdbc(DataSource dataSource) {
        return new NamedParameterJdbcTemplate(dataSource);
    }
}
