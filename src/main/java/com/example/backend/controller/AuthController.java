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

            // 🔹 Google
            if (attrs.containsKey("sub")) {
                String email = (String) attrs.get("email");

                var user = userRepo.findByEmail(email).orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setName((String) attrs.get("name"));
                    newUser.setProvider("google");
                    return userRepo.save(newUser);
                });

                String token = jwtService.generateToken(user);

                return ResponseEntity.ok(new AuthResponse(token, user.getEmail(), user.getName()));
            }
            // 🔹 GitHub
            else if (attrs.containsKey("login")) {
                String login = (String) attrs.get("login");
                String tempEmail = (String) attrs.get("email"); // pode ser null

                final String email;
                if (tempEmail == null || tempEmail.isBlank()) {
                    email = login + "@github.com"; // fallback se o email não vier
                } else {
                    email = tempEmail;
                }

                var user = userRepo.findByEmail(email).orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setName(login);
                    newUser.setProvider("github");
                    return userRepo.save(newUser);
                });

                String token = jwtService.generateToken(user);

                return ResponseEntity.ok(new AuthResponse(token, user.getEmail(), user.getName()));
            }
        }

        // 🔹 Credenciais normais
        if (authentication.getPrincipal() instanceof User user) {
            String token = jwtService.generateToken(user);
            return ResponseEntity.ok(new AuthResponse(token, user.getEmail(), user.getName()));
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
