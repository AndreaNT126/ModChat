package com.ModChat.backend.config;

import com.ModChat.backend.auth.service.JwtTokenProvider;
import com.ModChat.backend.shared.exception.AppException;
import com.nimbusds.jose.JOSEException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.text.ParseException;
import java.util.Objects;

@Component
public class CustomJwtDecoder implements JwtDecoder {
    @Value("${SECRET_KEY}")
    private String signerKey;

    private final JwtTokenProvider jwtTokenProvider;

    private NimbusJwtDecoder nimbusJwtDecoder = null;

    public CustomJwtDecoder(JwtTokenProvider  jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }
    @Override
    public Jwt decode(String token) throws JwtException {
        boolean response = true;
        try {
            jwtTokenProvider.verifyToken(token);
        } catch (AppException | JOSEException | ParseException e) {
            response = false;
        }

        if (!response) throw new JwtException("Token invalid");

        if (Objects.isNull(nimbusJwtDecoder)) {
            SecretKeySpec secretKeySpec = new SecretKeySpec(signerKey.getBytes(), "HS512");
            nimbusJwtDecoder = NimbusJwtDecoder.withSecretKey(secretKeySpec)
                    .macAlgorithm(MacAlgorithm.HS512)
                    .build();
        }

        return nimbusJwtDecoder.decode(token);
    }
}
