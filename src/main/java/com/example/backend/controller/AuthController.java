package com.example.backend.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;

import com.example.backend.repository.UserRepository;
import com.example.backend.model.LoginRequest;
import com.example.backend.model.AuthResponse;
import com.example.backend.model.User;
import com.example.backend.service.JwtService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.core.Authentication;

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

        if (authentication.getPrincipal() instanceof org.springframework.security.oauth2.core.user.OAuth2User oAuth2User) {
            return ResponseEntity.ok(oAuth2User.getAttributes());
        }

        if (authentication.getPrincipal() instanceof org.springframework.security.core.userdetails.User user) {
            return ResponseEntity.ok(Map.of(
                "email", user.getUsername(),
                "name", "Usuário com credenciais",
                "picture", ""
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
