package com.sqy.jwt.service.impl;

import java.time.Instant;
import java.util.*;

import com.sqy.jwt.domain.User;
import com.sqy.jwt.domain.security.AccessToken;
import com.sqy.jwt.domain.security.AuthenticationRequest;
import com.sqy.jwt.domain.security.JwtAuthenticationResponseTokens;
import com.sqy.jwt.domain.security.RefreshToken;
import com.sqy.jwt.dto.UserDto;
import com.sqy.jwt.service.RefreshTokenService;
import com.sqy.jwt.service.UserService;
import com.sqy.jwt.service.mapper.UserMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncodingException;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationService {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationService.class);
    private static final List<String> DEFAULT_USER_ROLES = List.of("ROLE_USER");
    private final JwtEncoder jwtEncoder;
    private final UserService userService;
    private final JwtClaimsBuilder jwtClaimsBuilder;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;

    public JwtAuthenticationService(JwtEncoder jwtEncoder, UserService userService, JwtClaimsBuilder jwtClaimsBuilder,
                                    RefreshTokenService refreshTokenService, PasswordEncoder passwordEncoder, UserMapper userMapper) {
        this.jwtEncoder = jwtEncoder;
        this.userService = userService;
        this.jwtClaimsBuilder = jwtClaimsBuilder;
        this.refreshTokenService = refreshTokenService;
        this.passwordEncoder = passwordEncoder;
        this.userMapper = userMapper;
    }

    public ResponseEntity<Void> register(AuthenticationRequest authenticationRequest) {
        String login = authenticationRequest.login();
        String password = passwordEncoder.encode(authenticationRequest.password());

        User user = new User(null, login, password, DEFAULT_USER_ROLES);
        boolean status = userService.register(user);
        if (status) {
            return ResponseEntity.ok().build();
        }
        return ResponseEntity.badRequest().build();
    }

    public ResponseEntity<JwtAuthenticationResponseTokens> login(AuthenticationRequest authenticationRequest) {
        String login = authenticationRequest.login();

        User loginedUser = userService.findUserByUsername(login);
        if (loginedUser == null || !passwordEncoder.matches(authenticationRequest.password(), loginedUser.encodedPassword())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        try {
            UserDto userDto = userMapper.toDto(loginedUser);

            Jwt accessToken = jwtEncoder.encode(jwtClaimsBuilder.params(userDto, false));
            Jwt refreshToken = jwtEncoder.encode(jwtClaimsBuilder.params(userDto, true));

            AccessToken accessTokenDto = new AccessToken(accessToken.getTokenValue(), accessToken.getExpiresAt());
            RefreshToken refreshTokenDto = new RefreshToken(refreshToken.getTokenValue(), refreshToken.getExpiresAt());

            JwtAuthenticationResponseTokens responseTokens = new JwtAuthenticationResponseTokens(accessTokenDto, refreshTokenDto);
            return ResponseEntity.ok(responseTokens);
        } catch (JwtEncodingException e) {
            logger.info("Exception while creating JWT!", e);
        }
        return ResponseEntity.badRequest().build();
    }

    public ResponseEntity<AccessToken> refresh(Jwt jwt) {
        String username = jwt.getSubject();
        List<String> roles = userService.findRolesByUsername(username);

        UserDto userDto = new UserDto(username, roles);
        Jwt accessJwt;
        try {
            accessJwt = jwtEncoder.encode(jwtClaimsBuilder.params(userDto, false));
        } catch (JwtEncodingException e) {
            logger.warn("Invoke refresh with exception.", e);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        AccessToken accessToken = new AccessToken(accessJwt.getTokenValue(), accessJwt.getExpiresAt());
        return ResponseEntity.ok(accessToken);
    }

    public ResponseEntity<Void> logout(Jwt jwt) {
        String tokenValue = jwt.getTokenValue();
        Instant expiresAt = jwt.getExpiresAt();

        RefreshToken refreshToken = new RefreshToken(tokenValue, expiresAt);
        refreshTokenService.save(refreshToken);
        return ResponseEntity.ok().build();
    }
}
