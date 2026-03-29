package com.ModChat.backend.auth.controller;

import com.ModChat.backend.auth.dto.AuthResponse;
import com.ModChat.backend.auth.dto.RequestSignIn;
import com.ModChat.backend.auth.dto.RequestSignUp;
import com.ModChat.backend.auth.service.AuthService;
import com.ModChat.backend.shared.abstractBase.ApiResponse;
import com.ModChat.backend.shared.utils.KeyCookie;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@Slf4j
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenController {
    private AuthService authService;

    @PostMapping(value = "/auth/sign-up")
    ResponseEntity<ApiResponse<?>> signup(@RequestBody RequestSignUp request){
        String res = authService.signUp(request);
        return ResponseEntity.ok().body(new ApiResponse<>(HttpStatus.CREATED.value(),null,null));
    };

    @PostMapping(value = "/auth/sign-in")
    ResponseEntity<ApiResponse<?>> signIn(@RequestBody RequestSignIn request){
        AuthResponse res = authService.signIn(request);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,res.getCookie().toString())
                .body(new ApiResponse<>(HttpStatus.OK.value(),"Đăng nhập thành công",res.getAccessToken()));
    };

    @PostMapping("/auth/refresh-token")
    public ResponseEntity<?> refreshToken(
            @CookieValue(name = KeyCookie.REFRESH_TOKEN, required = false) String refreshToken) {
        String accessToken = authService.refreshToken(refreshToken);
        return ResponseEntity.ok()
                .body(new ApiResponse<>(HttpStatus.OK.value(),null,accessToken));
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<?> logout(
            @CookieValue(name = KeyCookie.REFRESH_TOKEN, required = false) String refreshToken) {
        ResponseCookie deleteCookie = authService.logout(refreshToken);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,deleteCookie.toString())
                .body(new ApiResponse<>(HttpStatus.OK.value(),"Đã đăng xuất khỏi hệ thống",null));
    }
}
