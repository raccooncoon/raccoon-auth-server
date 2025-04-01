package com.raccoon.auth.controller;

import com.raccoon.auth.domain.User;
import com.raccoon.auth.dto.LoginRequest;
import com.raccoon.auth.dto.SignupRequest;
import com.raccoon.auth.dto.TokenResponse;
import com.raccoon.auth.jwt.JwtService;
import com.raccoon.auth.repository.UserRepository;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RedisTemplate<String, String> redisTemplate;

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignupRequest req) {
        if (userRepository.existsByUsername(req.getUsername()) || userRepository.existsByEmail(req.getEmail())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("이미 존재하는 사용자명 또는 이메일입니다.");
        }

        User user = User.builder()
                .username(req.getUsername())
                .password(passwordEncoder.encode(req.getPassword()))
                .email(req.getEmail())
                .nickname(req.getNickname())
                .role("ROLE_USER")
                .build();

        userRepository.save(user);
        return ResponseEntity.ok("회원가입 성공");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        User user = userRepository.findByUsername(req.getUsername())
                .orElseThrow(() -> new RuntimeException("사용자 없음"));

        if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("비밀번호 불일치");
        }

        String accessToken = jwtService.createAccessToken(user.getUsername(), user.getRole());
        String refreshToken = jwtService.createRefreshToken(user.getUsername());

        redisTemplate.opsForValue().set("RT:" + user.getUsername(), refreshToken, 7, TimeUnit.DAYS);

        return ResponseEntity.ok(new TokenResponse(accessToken, refreshToken));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> body) {
        String oldRefreshToken = body.get("refreshToken");

        Claims claims = jwtService.parseToken(oldRefreshToken);
        String username = claims.getSubject();

        String saved = redisTemplate.opsForValue().get("RT:" + username);
        if (!oldRefreshToken.equals(saved)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("RefreshToken이 유효하지 않습니다.");
        }

        String newAccessToken = jwtService.createAccessToken(username, claims.get("role").toString());
        return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refreshToken");
        String username = jwtService.parseToken(refreshToken).getSubject();
        redisTemplate.delete("RT:" + username);
        return ResponseEntity.ok("로그아웃 완료");
    }
}