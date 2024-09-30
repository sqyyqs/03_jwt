package com.sqy.jwt.controller;

import com.sqy.jwt.domain.security.AccessToken;
import com.sqy.jwt.domain.security.AuthenticationRequest;
import com.sqy.jwt.domain.security.JwtAuthenticationResponseTokens;
import com.sqy.jwt.service.impl.JwtAuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final JwtAuthenticationService jwtAuthenticationService;

    public AuthController(JwtAuthenticationService jwtAuthenticationService) { this.jwtAuthenticationService = jwtAuthenticationService; }

    @PostMapping("/register")
    @Operation(summary = "Регистрация по логину и паролю",
               responses = {
                   @ApiResponse(responseCode = "200", description = "Успешная регистрация"),
                   @ApiResponse(responseCode = "400", description = "Пользователь с таким именем уже существует")
               })
    public ResponseEntity<Void> register(@RequestBody AuthenticationRequest authenticationRequest) {
        return jwtAuthenticationService.register(authenticationRequest);
    }

    @PostMapping("/login")
    @Operation(summary = "Вход по логину и паролю",
               responses = {
                   @ApiResponse(responseCode = "200", description = "Успешный логин"),
                   @ApiResponse(responseCode = "403", description = "Неверный пароль"),
                   @ApiResponse(responseCode = "400", description = "Что-то пошло не так с созданием jwt"),
               })
    public ResponseEntity<JwtAuthenticationResponseTokens> login(@RequestBody AuthenticationRequest authenticationRequest) {
        return jwtAuthenticationService.login(authenticationRequest);
    }

    @PostMapping("/refresh")
    @PreAuthorize("hasAuthority('REFRESH')")
    @Operation(summary = "Обновление токена (выдача нового access по refresh)",
               responses = {
                   @ApiResponse(responseCode = "200", description = "Успешно выдан новый токен"),
                   @ApiResponse(responseCode = "403", description = "По какой-то причине не удалось обновить токен"),
                   @ApiResponse(responseCode = "401", description = "Если что-то не так с Bearer Token'ом(истекший срок действия, невалидный, ...)"),
               })
    public ResponseEntity<AccessToken> refresh(@AuthenticationPrincipal Jwt jwt) {
        return jwtAuthenticationService.refresh(jwt);
    }

    @PostMapping("/logout")
    @PreAuthorize("hasAuthority('LOGOUT')")
    @Operation(summary = "Отзыв токена (сохранение его в базу данных)",
               responses = @ApiResponse(responseCode = "200", description = "Успешно сохранен, больше по токену не зайти"))
    public ResponseEntity<Void> logout(@AuthenticationPrincipal Jwt jwt) {
        return jwtAuthenticationService.logout(jwt);
    }
}
