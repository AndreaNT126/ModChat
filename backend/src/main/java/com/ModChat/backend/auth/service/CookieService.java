package com.ModChat.backend.auth.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Component;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.REFRESH_TOKEN;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class CookieService {

    public void sendRefreshToken(String token, HttpServletResponse response) {
        Cookie cookie = new Cookie(REFRESH_TOKEN, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // Dùng HTTPS
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60 * 24); // 15 phút
        cookie.setDomain("localhost"); // Thay đổi theo tên miền của bạn

        response.addCookie(cookie);
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
        accessCookie.setDomain("localhost"); // Thay đổi theo tên miền của bạn

        response.addCookie(accessCookie);
    }
}
