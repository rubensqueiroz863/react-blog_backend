package com.example.backend.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;
import com.example.backend.model.User;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;
import java.util.UUID;

@Service
public class JwtService {

    private final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    // Tempo de expiração
    private final long ACCESS_EXPIRATION = 1000 * 60 * 60;       // 1 hora
    private final long REFRESH_EXPIRATION = 1000 * 60 * 60 * 24 * 7; // 7 dias

    // 🔹 Access Token
    public String generateAccessToken(User user) {
        return buildToken(user, ACCESS_EXPIRATION, "access");
    }

    public String generateRefreshToken(User user) {
        return buildToken(user, REFRESH_EXPIRATION, "refresh");
    }

    private String buildToken(User user, long expiration, String type) {
        return Jwts.builder()
                .setId(UUID.randomUUID().toString()) // 👈 garante unicidade
                .setSubject(user.getEmail())
                .claim("id", user.getId())
                .claim("name", user.getName())
                .claim("type", type)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(key)
                .compact();
    }

    // 🔹 Extrações e validações
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public boolean isTokenValid(String token, User user) {
        try {
            final String username = extractUsername(token);
            return username.equals(user.getEmail()) && !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
