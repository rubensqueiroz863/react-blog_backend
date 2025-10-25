package com.example.backend.controller;

import org.springframework.http.ResponseEntity;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.backend.model.User;
import com.example.backend.model.LoginRequest;
import com.example.backend.model.AuthResponse;
import com.example.backend.repository.UserRepository;
import com.example.backend.service.JwtService;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class AuthController {

    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthController(UserRepository userRepo, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    // 🔹 Obter usuário atual
    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication authentication) {
        if (authentication == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if (authentication.getPrincipal() instanceof OAuth2User oAuth2User) {
            var attrs = oAuth2User.getAttributes();

            if (attrs.containsKey("sub")) { // Google
                String email = (String) attrs.get("email");

                var user = userRepo.findByEmail(email).orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setName((String) attrs.get("name"));
                    newUser.setProvider("google");
                    return userRepo.save(newUser);
                });

                String accessToken = jwtService.generateAccessToken(user);
                String refreshToken = jwtService.generateRefreshToken(user);

                return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken, user.getEmail(), user.getName()));
            }
        }

        if (authentication.getPrincipal() instanceof User user) {
            String accessToken = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);
            return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken, user.getEmail(), user.getName()));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    // 🔹 Registro
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        if (userRepo.findByEmail(user.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().body("Email já cadastrado");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setProvider("credentials");
        userRepo.save(user);
        return ResponseEntity.ok("Usuário registrado");
    }

    // 🔹 Login
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        var user = userRepo.findByEmail(req.getEmail())
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Senha inválida");
        }

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken, user.getEmail(), user.getName()));
    }

    // 🔹 Refresh Token
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refreshToken");
        try {
            String email = jwtService.extractUsername(refreshToken);
            var user = userRepo.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

            if (!jwtService.isTokenValid(refreshToken, user)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token inválido");
            }

            String newAccessToken = jwtService.generateAccessToken(user);
            return ResponseEntity.ok(new AuthResponse(newAccessToken, refreshToken, user.getEmail(), user.getName()));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token expirado ou inválido");
        }
    }
}
