package com.sqy.jwt.security;

import java.text.ParseException;
import java.time.Instant;
import java.util.*;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtEncodingException;
import org.springframework.stereotype.Component;

@Component
public class JwtEncoderImpl implements JwtEncoder {
    private static final Logger logger = LoggerFactory.getLogger(JwtEncoderImpl.class);
    private final JWSSigner jwsSigner;
    private final JWEEncrypter jweEncrypter;
    private final EncryptionMethod encryptionMethod;

    public JwtEncoderImpl(JWSSigner jwsSigner, JWEEncrypter jweEncrypter, EncryptionMethod encryptionMethod) {
        this.jwsSigner = jwsSigner;
        this.jweEncrypter = jweEncrypter;
        this.encryptionMethod = encryptionMethod;
    }

    @Override
    public Jwt encode(JwtEncoderParameters parameters) {
        JwsHeader jwsHeader = parameters.getJwsHeader();
        JwtClaimsSet claims = parameters.getClaims();

        try {
            SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.parse(jwsHeader.getAlgorithm().getName())).build(),
                JWTClaimsSet.parse(mapClaims(claims.getClaims()))
            );

            signedJWT.sign(jwsSigner);

            JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(
                    JWEAlgorithm.parse(jwsHeader.getHeader(HeaderParameterNames.ENCRYPTION_ALGORITHM)),
                    encryptionMethod
                ).contentType("JWT").build(),
                new Payload(signedJWT)
            );

            jweObject.encrypt(jweEncrypter);
            return new Jwt(jweObject.serialize(), claims.getIssuedAt(), claims.getExpiresAt(), jwsHeader.getHeaders(), claims.getClaims());
        } catch (ParseException | JOSEException e) {
            logger.warn("Invoke encode({}) with exception.", parameters, e);
            throw new JwtEncodingException("Exception while issuing jwt!", e);
        }
    }

    private static Map<String, Object> mapClaims(Map<String, Object> claims) {
        Map<String, Object> newClaims = new HashMap<>();
        claims.keySet().forEach(key -> {
            switch (key) {
                case JwtClaimNames.EXP, JWTClaimNames.ISSUED_AT -> newClaims.put(key, ((Instant) claims.get(key)).getEpochSecond());
                default -> newClaims.put(key, claims.get(key));
            }
        });
        return newClaims;
    }
}
