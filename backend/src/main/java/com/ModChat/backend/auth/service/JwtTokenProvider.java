package com.ModChat.backend.auth.service;

import com.ModChat.backend.auth.model.User;
import com.ModChat.backend.shared.exception.AppException;
import com.ModChat.backend.shared.exception.ErrorCode;
import com.ModChat.backend.shared.utils.TypeTokenJWT;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Component
@FieldDefaults(makeFinal = true, level = lombok.AccessLevel.PRIVATE)
@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {
    @NonFinal
    @Value("${SECRET_KEY}")
    protected String SECRET_KEY;

    @NonFinal
    @Value("${SECRET_KEY_REFRESH}")
    protected String REFRESH_KEY;

    @NonFinal
    @Value("${VALID_DURATION}")
    protected long VALID_DURATION;

    @NonFinal
    @Value("${VALID_DURATION_REFRESH}")
    protected long REFRESHABLE_DURATION;

    public String generateAccessToken(User user) {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getId().toString())
                .issuer("ModChat")
                .issueTime(new Date())
                .expirationTime(new Date(
                        Instant.now().plus(VALID_DURATION, ChronoUnit.SECONDS).toEpochMilli()
                ))
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", buildScope(user))
                .build();

        try {
            Payload payload = new Payload(jwtClaimsSet.toJSONObject());
            JWSObject jwsObject = new JWSObject(header, payload);
            jwsObject.sign(new MACSigner(SECRET_KEY.getBytes()));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            log.error("Cannot create access token", e);
            throw new RuntimeException(e);
        }
    }

    public String generateRefreshToken() {
        byte[] randomBytes = new byte[32]; // 256-bit
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    public SignedJWT verifyToken(String token) throws JOSEException, ParseException {
        // Select the appropriate secret key based on whether it is a refresh token or access token
        JWSVerifier verifier = new MACVerifier(SECRET_KEY.getBytes());
        // Parse the token
        SignedJWT signedJWT = SignedJWT.parse(token);

        // Get the expiration time from the claims
        Date expiryTime = signedJWT.getJWTClaimsSet().getExpirationTime();
        Date currentTime = new Date();

        // Verify the token's signature and check its expiration
        boolean verified = signedJWT.verify(verifier);

        // Check if the token is both valid (signature verified) and not expired
        if (!verified) {
            throw new AppException(ErrorCode.TOKEN_FAIL);
        }

        // Check if the token has been invalidated
        if (expiryTime.before(currentTime)) {
            throw new AppException(ErrorCode.TOKEN_EXPIRED);
        }
        // If everything is valid, return the signedJWT
        return signedJWT;
    }

    private String buildScope(User user) {
        if (user.getRole() == null) return "";

        // Chỉ cần trả về tên Role với tiền tố ROLE_
        return "ROLE_" + user.getRole().getName();
    }

    private record TokenInfo(String token, Date expiryDate) {}
}
