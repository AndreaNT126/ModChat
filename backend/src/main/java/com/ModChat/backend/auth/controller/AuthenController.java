package com.ModChat.backend.auth.controller;

import com.ModChat.backend.auth.dto.RequestSignUp;
import com.ModChat.backend.auth.service.AuthService;
import com.ModChat.backend.shared.abstractBase.ApiResponse;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenController {
    private AuthService authService;

    @PostMapping(value = "/auth/sign-up")
    ApiResponse<String> authenticate(@RequestBody RequestSignUp request){
        return new ApiResponse<>(HttpStatus.CREATED.value(),authService.signUp(request),null);
    };
}
