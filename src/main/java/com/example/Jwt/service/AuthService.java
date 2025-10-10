package com.example.Jwt.service;

import com.example.Jwt.dto.AuthToken;
import com.example.Jwt.dto.LoginRequest;
import com.example.Jwt.dto.SignupRequest;
import com.example.Jwt.model.RefreshToken;
import com.example.Jwt.model.User;
import com.example.Jwt.repository.UserRepository;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthService(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          JwtService jwtService,
                          RefreshTokenService refreshTokenService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    public User signup(SignupRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new BadCredentialsException("Email already in use");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        return userRepository.save(user);
    }

    public AuthToken login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new BadCredentialsException("Wrong email or password"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Wrong email or password");
        }

        String accessToken = jwtService.generateAccessToken(user);
        RefreshToken refreshTokenEntity = refreshTokenService.createRefreshToken(user.getId());
        String refreshToken = refreshTokenEntity.getToken();

        return new AuthToken(accessToken, refreshToken);
    }

    public String refreshAccessToken(String refreshTokenValue) {
        RefreshToken refreshToken=refreshTokenService.findByToken(refreshTokenValue)
                .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));
        refreshTokenService.verifyExpiration(refreshToken);
        User user = refreshToken.getUser();
        return jwtService.generateAccessToken(user);

    }


    public void logout(String refreshTokenValue) {
        if (refreshTokenValue == null) {
            return;
        }

        RefreshToken refreshToken = refreshTokenService.findByToken(refreshTokenValue).orElse(null);
        if (refreshToken != null) {
            refreshTokenService.deleteById(refreshToken.getId());
        }
    }
}
