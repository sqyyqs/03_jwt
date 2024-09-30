package com.sqy.jwt;

import java.util.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sqy.jwt.domain.security.AuthenticationRequest;
import com.sqy.jwt.dto.UserDto;
import com.sqy.jwt.service.impl.JwtAuthenticationService;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@SpringBootTest
@AutoConfigureMockMvc
public class AuthControllerTest {
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private TestJwtCreator testJwtCreator;
    @Autowired
    private ObjectMapper objectMapper;
    @MockBean
    private JwtAuthenticationService authenticationService;

    @Test
    void testNoAccessWithoutToken() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/auth/refresh"))
            .andExpect(MockMvcResultMatchers.status().is(HttpStatus.UNAUTHORIZED.value()));
    }

    @Test
    void testNoAccessToRefreshWithAccessToken() throws Exception {
        String accessToken = testJwtCreator.accessToken(new UserDto("admin", List.of("NO_REFRESH")));
        mockMvc.perform(MockMvcRequestBuilders.post("/auth/refresh")
                .header("Authorization", "Bearer " + accessToken))
            .andExpect(MockMvcResultMatchers.status().is(HttpStatus.FORBIDDEN.value()));
    }

    @Test
    void testNoAccessToLogoutWithAccessToken() throws Exception {
        String accessToken = testJwtCreator.accessToken(new UserDto("admin", List.of("NO_LOGOUT")));
        mockMvc.perform(MockMvcRequestBuilders.post("/auth/logout")
                .header("Authorization", "Bearer " + accessToken))
            .andExpect(MockMvcResultMatchers.status().is(HttpStatus.FORBIDDEN.value()));
    }

    @Test
    void testLoginAndRegisterIsOpen() throws Exception {
        UserDto mockUser = new UserDto("admin", Collections.singletonList("COOL_GUY"));

        Mockito.when(authenticationService.login(Mockito.any(AuthenticationRequest.class))).thenReturn(
            ResponseEntity.ok(testJwtCreator.tokens(mockUser))
        );
        Mockito.when(authenticationService.register(Mockito.any(AuthenticationRequest.class))).thenReturn(
            ResponseEntity.ok().build()
        );

        String body = objectMapper.writeValueAsString(new AuthenticationRequest("admin", "admin"));

        mockMvc.perform(MockMvcRequestBuilders.post("/auth/login")
                .content(body)
                .contentType(MediaType.APPLICATION_JSON_VALUE))
            .andExpect(MockMvcResultMatchers.status().isOk());

        mockMvc.perform(MockMvcRequestBuilders.post("/auth/register")
                .content(body)
                .contentType(MediaType.APPLICATION_JSON_VALUE))
            .andExpect(MockMvcResultMatchers.status().isOk());
    }

    @Test
    void testAccessToRefreshAndLogout() throws Exception {
        UserDto mockUser = new UserDto("admin", Collections.singletonList("COOL_GUY"));

        Mockito.when(authenticationService.refresh(Mockito.any(Jwt.class))).thenReturn(
            ResponseEntity.ok(testJwtCreator.accessTokenEntity(mockUser))
        );
        Mockito.when(authenticationService.logout(Mockito.any(Jwt.class))).thenReturn(
            ResponseEntity.ok().build()
        );

        String refreshToken = testJwtCreator.refreshToken(mockUser);

        mockMvc.perform(MockMvcRequestBuilders.post("/auth/refresh")
                .header("Authorization", "Bearer " + refreshToken))
            .andExpect(MockMvcResultMatchers.status().isOk());

        mockMvc.perform(MockMvcRequestBuilders.post("/auth/logout")
                .header("Authorization", "Bearer " + refreshToken))
            .andExpect(MockMvcResultMatchers.status().isOk());
    }

}