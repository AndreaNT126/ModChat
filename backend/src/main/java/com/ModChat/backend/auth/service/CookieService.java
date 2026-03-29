package com.ModChat.backend.auth.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.REFRESH_TOKEN;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class CookieService {

    public void CreateCookie(String token) {
        ResponseCookie cookie = ResponseCookie.from("refreshToken", token)
                .httpOnly(true)     // chống XSS
                .secure(true)       // chỉ gửi qua HTTPS
                .path("/")
                .maxAge(60 * 60)    // 1 giờ
                .sameSite("none") // CSRF protection
                .build();
    }

    public String getCookieByKey(HttpServletRequest request, String key) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (key.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    public void deleteCookie(HttpServletResponse response,String key) {
        Cookie accessCookie = new Cookie(key, null);
        accessCookie.setHttpOnly(true);
        accessCookie.setSecure(false); // Dùng HTTPS
        accessCookie.setPath("/");
        accessCookie.setMaxAge(0); // Xóa cookie
        accessCookie.setDomain(""); // Thay đổi theo tên miền của bạn

        response.addCookie(accessCookie);
    }
}
