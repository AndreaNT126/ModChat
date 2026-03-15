package com.ModChat.backend.auth.service;

import com.ModChat.backend.auth.dto.RequestSignUp;
import com.ModChat.backend.auth.model.Role;
import com.ModChat.backend.auth.model.User;
import com.ModChat.backend.auth.repository.RoleRepo;
import com.ModChat.backend.auth.repository.UserRepo;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthService {
    UserRepo userRepo;
    RoleRepo roleRepo;
    ModelMapper modelMapper;
    PasswordEncoder passwordEncoder;

    public String signUp(RequestSignUp requestSignUp){
        Role role = roleRepo.findById(2).orElseThrow(() ->  new RuntimeException("Không có role phu hợp."));

        String passwordHashing = passwordEncoder.encode(requestSignUp.getPassword());

        User user = new User();
        user.setEmail(requestSignUp.getEmail());
        user.setStatus("active");
        user.setUsername(requestSignUp.getUsername());
        user.setRole(role);
        user.setName(requestSignUp.getName());
        user.setHashingPassword(passwordHashing);

        userRepo.save(user);

        return "Đã thêm user thành công.";
    }
}
