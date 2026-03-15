package com.ModChat.backend.auth.dto;

import com.ModChat.backend.auth.model.Role;
import jakarta.persistence.*;
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
    Integer role;
}
