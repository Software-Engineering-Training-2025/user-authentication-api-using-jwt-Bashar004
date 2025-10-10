package com.example.Jwt.controller;

import com.example.Jwt.model.User;
import com.example.Jwt.repository.UserRepository;
import com.example.Jwt.service.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserController {
    @Autowired
    private JwtService jwtService;
    @Autowired
    UserRepository userRepository;

    @Value("${app.cookie.access-token.name}")
    private String accessTokenCookieName;

    @GetMapping
    public ResponseEntity<?> getCurrentUser(HttpServletRequest request) {
        String accessToken = getAccessTokenFromCookies(request);
        if (accessToken == null || !jwtService.validateToken(accessToken)) {
            return ResponseEntity.status(401).body("Invalid or Expired token");
        }

        Long userId = jwtService.getUserIdFromToken(accessToken);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return ResponseEntity.ok(Map.of(
                "username", user.getUsername(),
                "email", user.getEmail()
        ));
    }

    private String getAccessTokenFromCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (accessTokenCookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
