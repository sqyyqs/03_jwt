package com.sqy.jwt.security;

import java.text.ParseException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sqy.jwt.domain.security.RefreshToken;
import com.sqy.jwt.service.RefreshTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

@Component
public class JwtDecoderImpl implements JwtDecoder {
    private static final Logger logger = LoggerFactory.getLogger(JwtDecoderImpl.class);
    private final JWSVerifier jwsVerifier;
    private final JWEDecrypter jweDecrypter;
    private final RefreshTokenService refreshTokenService;

    public JwtDecoderImpl(JWSVerifier jwsVerifier, JWEDecrypter jweDecrypter, RefreshTokenService refreshTokenService) {
        this.jwsVerifier = jwsVerifier;
        this.jweDecrypter = jweDecrypter;
        this.refreshTokenService = refreshTokenService;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        if (refreshTokenService.isRevoked(new RefreshToken(token, null))) {
            throw new BadJwtException("Token is revoked!");
        }
        try {
            JWEObject jweObject = JWEObject.parse(token);
            jweObject.decrypt(jweDecrypter);

            SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
            signedJWT.verify(jwsVerifier);

            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

            return new Jwt(token,
                jwtClaimsSet.getIssueTime().toInstant(),
                jwtClaimsSet.getExpirationTime().toInstant(),
                signedJWT.getHeader().toJSONObject(),
                signedJWT.getJWTClaimsSet().toJSONObject()
            );
        } catch (ParseException | JOSEException e) {
            logger.warn("Invoke decode() with exception.", e);
            throw new JwtException("Exception while decoding jwt!", e);
        }
    }
}
