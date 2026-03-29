package com.ModChat.backend.auth.service;

import com.ModChat.backend.auth.dto.AuthResponse;
import com.ModChat.backend.auth.dto.RequestSignIn;
import com.ModChat.backend.auth.dto.RequestSignUp;
import com.ModChat.backend.auth.model.Role;
import com.ModChat.backend.auth.model.User;
import com.ModChat.backend.auth.repository.RoleRepo;
import com.ModChat.backend.auth.repository.UserRepo;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthService {
    UserRepo userRepo;
    RoleRepo roleRepo;
    ModelMapper modelMapper;
    PasswordEncoder passwordEncoder;
    AuthenticationManager authenticationManager;
    JwtTokenProvider jwtTokenProvider;
    SessionService sessionService;

    public String signUp(RequestSignUp requestSignUp, Integer roleId){
        Role role = roleRepo.findById(roleId).orElseThrow(() ->  new RuntimeException("Not found role in system"));

        String passwordHashing = passwordEncoder.encode(requestSignUp.getPassword());

        User user = modelMapper.map(requestSignUp,User.class);
        user.setRole(role);
        user.setHashingPassword(passwordHashing);
        user.setStatus("active");

        userRepo.save(user);

        return "Đã thêm tài khoản mới thành công.";
    }

    public AuthResponse signIn(RequestSignIn request){
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        User currentUser = (User) authentication.getPrincipal();

        String accessToken = jwtTokenProvider.generateAccessToken(currentUser);

        ResponseCookie refreshCookie = sessionService.openSession(currentUser);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .cookie(refreshCookie)
                .build();
    }

    public String refreshToken(String refreshToken){
        User user = sessionService.checkRefreshToken(refreshToken);
        return jwtTokenProvider.generateAccessToken(user);
    }

    public ResponseCookie logout(String refreshToken){
        ResponseCookie deleteCookie = sessionService.closeSession(refreshToken);

        return deleteCookie;
    }
}
