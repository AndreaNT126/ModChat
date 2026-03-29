package com.ModChat.backend.auth.repository;

import com.ModChat.backend.auth.model.Session;
import com.ModChat.backend.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SessionRepo extends JpaRepository<Session,Integer> {
    Optional<Session> findByRefreshToken(String token);
}
