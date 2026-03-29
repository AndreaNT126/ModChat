package com.ModChat.backend.auth.dto;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class RequestSignUp {
    String email;
    String name;
    String password;
    String username;
}
