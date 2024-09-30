package com.sqy.jwt.configuration.security;

import java.text.ParseException;
import java.util.*;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .cors(AbstractHttpConfigurer::disable)
            .csrf(AbstractHttpConfigurer::disable)
            .oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt(Customizer.withDefaults()))
            .sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JWSSigner jwsSigner(
        @Value("${spring.security.oauth2.resourceserver.jwt.private-key}") String privateKey) throws ParseException, JOSEException {
        return new ECDSASigner(ECKey.parse(privateKey));
    }

    @Bean
    public JWSVerifier jwsVerifier(
        @Value("${spring.security.oauth2.resourceserver.jwt.private-key}") String privateKey) throws ParseException, JOSEException {
        return new ECDSAVerifier(ECKey.parse(privateKey));
    }

    @Bean
    public EncryptionMethod encryptionMethod(@Value("${spring.security.oauth2.resourceserver.jwt.enc-method}") String encryptionMethod) {
        return EncryptionMethod.parse(encryptionMethod);
    }

    @Bean
    public JWEDecrypter jweDecrypter(@Value("${spring.security.oauth2.resourceserver.jwt.secret-key}") String secretKey) throws KeyLengthException {
        SecretKeySpec aes = new SecretKeySpec(Base64.getDecoder().decode(secretKey), "AES");
        return new AESDecrypter(aes);
    }

    @Bean
    public JWEEncrypter jweEncrypter(@Value("${spring.security.oauth2.resourceserver.jwt.secret-key}") String secretKey) throws JOSEException {
        SecretKeySpec aes = new SecretKeySpec(Base64.getDecoder().decode(secretKey), "AES");
        return new AESEncrypter(aes);
    }
}
