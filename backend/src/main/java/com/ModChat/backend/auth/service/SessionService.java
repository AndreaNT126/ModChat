package com.ModChat.backend.auth.service;

import com.ModChat.backend.auth.model.Session;
import com.ModChat.backend.auth.model.User;
import com.ModChat.backend.auth.repository.SessionRepo;
import com.ModChat.backend.shared.utils.KeyCookie;
import lombok.AccessLevel;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.Instant;

@Service
@Slf4j
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class SessionService {
    JwtTokenProvider jwtTokenProvider;
    SessionRepo sessionRepo;

    @NonFinal
    @Value("${VALID_DURATION_REFRESH}")
    protected long REFRESH_TOKEN_TTL;

    public ResponseCookie openSession(User user){
        String refreshToken = jwtTokenProvider.generateRefreshToken();

        ResponseCookie cookie = ResponseCookie.from(KeyCookie.REFRESH_TOKEN, refreshToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(REFRESH_TOKEN_TTL)
                .sameSite("none") // CSRF protection
                .build();

        Session session = new Session();
        session.setRefreshToken(refreshToken);

        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(REFRESH_TOKEN_TTL);
        session.setExpiresAt(Timestamp.from(expiry));
        session.setUser(user);
        session.setIsRevoked(false);

        sessionRepo.save(session);



        return cookie;
    }

    public ResponseCookie closeSession(String token){
        Session session = sessionRepo.findByRefreshToken(token).orElseThrow(() -> new RuntimeException("Invalid token"));

        if (session.getIsRevoked()) {
            throw new RuntimeException("Token revoked");
        }

        sessionRepo.delete(session);

        ResponseCookie deleteCookie = ResponseCookie.from(KeyCookie.REFRESH_TOKEN, "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(0)
                .sameSite("none") // CSRF protection
                .build();

        return deleteCookie;
    }

    public User checkRefreshToken(String Token){
        Session session = sessionRepo.findByRefreshToken(Token).orElseThrow(() -> new RuntimeException("Invalid token"));

        if (session.getIsRevoked()) {
            throw new RuntimeException("Token revoked");
        }

        if (session.getExpiresAt().before(Timestamp.from(Instant.now()))) {
            throw new RuntimeException("Token expired");
        }

        return session.getUser();
    }


}
