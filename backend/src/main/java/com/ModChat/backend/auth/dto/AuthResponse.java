package com.ModChat.backend.auth.dto;

import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseCookie;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class AuthResponse {
    String accessToken;
    ResponseCookie cookie;
}
