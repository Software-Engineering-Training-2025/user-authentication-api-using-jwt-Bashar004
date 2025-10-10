package com.example.Jwt.controller;

import com.example.Jwt.dto.AuthToken;
import com.example.Jwt.dto.LoginRequest;
import com.example.Jwt.dto.SignupRequest;
import com.example.Jwt.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Map;
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {


private final AuthService authService;



@Value("${app.jwt.access-token.expiration}")
private long accessTokenExpirationMs;

@Value("${app.jwt.refresh-token.expiration}")
private long refreshTokenExpirationMs;

@Value("${app.cookie.access-token.name}")
private String accessTokenCookieName;

@Value("${app.cookie.refresh-token.name}")
private String refreshTokenCookieName;

@Value("${app.cookie.path}")
private String cookiePath;

@Value("${app.cookie.http-only}")
private boolean cookieHttpOnly;

@Value("${app.cookie.secure}")
private boolean cookieSecure;

@Value("${app.cookie.same-site}")
private String cookieSameSite;

private ResponseCookie createCookie(String name, String value, long maxAgeMs) {
    return ResponseCookie.from(name, value)
            .path(cookiePath)
            .httpOnly(cookieHttpOnly)
            .secure(cookieSecure)
            .sameSite(cookieSameSite)
            .maxAge(Duration.ofMillis(maxAgeMs))
            .build();
}

@PostMapping("/signup")
public ResponseEntity<?> signup( @RequestBody SignupRequest request) {
    authService.signup(request);
    return ResponseEntity.ok("User registered successfully");
}

@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    AuthToken tokens = authService.login(request);

    ResponseCookie accessCookie = createCookie(
            accessTokenCookieName,
            tokens.getAccessToken(),
            accessTokenExpirationMs
    );

    ResponseCookie refreshCookie = createCookie(
            refreshTokenCookieName,
            tokens.getRefreshToken(),
            refreshTokenExpirationMs
    );

    return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
            .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())

//            .body( "Login successful");

            .body(Map.of(
            "message", "Login successful",
            "accessToken", tokens.getAccessToken(),
            "refreshToken", tokens.getRefreshToken()
    ));



    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
     String refreshToken = getRefreshTokenFromCookies(request);
        authService.logout(refreshToken);


        return ResponseEntity.ok("User logged out");

    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request) {
        String refreshTokenValue = getRefreshTokenFromCookies(request);
        if (refreshTokenValue == null) {
            return ResponseEntity.status(401).body("Invalid or Expired token");
        }

        String newAccessToken = authService.refreshAccessToken(refreshTokenValue);

        ResponseCookie accessCookie = createCookie(
                accessTokenCookieName,
                newAccessToken,
                accessTokenExpirationMs
        );

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                .body( "Token refreshed");
    }



    private String getRefreshTokenFromCookies(HttpServletRequest request) {
        Cookie[] cookie =request.getCookies();
        if (cookie != null) {
            for (Cookie cookie1 : cookie) {
                if (cookie1.getName().equals(refreshTokenCookieName)) {
                    return cookie1.getValue();
                }
            }
        }
        return null;
    }

}



