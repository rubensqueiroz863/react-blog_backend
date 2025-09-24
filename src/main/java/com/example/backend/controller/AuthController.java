package com.example.backend.controller;

import org.springframework.http.ResponseEntity;
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

import java.util.Map;

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

    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication authentication) {
        if (authentication == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if (authentication.getPrincipal() instanceof OAuth2User oAuth2User) {
            var attrs = oAuth2User.getAttributes();

            // Detecta se é Google ou GitHub
            if (attrs.containsKey("sub")) {
                // Google
                return ResponseEntity.ok(Map.of(
                        "sub", attrs.get("sub"),
                        "email", attrs.get("email"),
                        "name", attrs.get("name"),
                        "picture", attrs.get("picture"),
                        "provider", "google"
                ));
            } else if (attrs.containsKey("login")) {
                // GitHub
                return ResponseEntity.ok(Map.of(
                        "sub", attrs.get("id"),
                        "email", attrs.get("email"), // pode ser null, GitHub nem sempre retorna email
                        "name", attrs.get("login"),
                        "picture", attrs.get("avatar_url"),
                        "provider", "github"
                ));
            }
        }

        if (authentication.getPrincipal() instanceof User user) {
            return ResponseEntity.ok(Map.of(
                    "sub", user.getId(),
                    "email", user.getEmail(),
                    "name", user.getName(),
                    "picture", "",
                    "provider", "credentials"
            ));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }





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

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        var user = userRepo.findByEmail(req.getEmail())
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Senha inválida");
        }

        String token = jwtService.generateToken(user);
        return ResponseEntity.ok(new AuthResponse(token, user.getEmail(), user.getName()));
    }
}
