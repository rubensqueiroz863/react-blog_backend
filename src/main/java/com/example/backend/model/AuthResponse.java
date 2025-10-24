package com.example.backend.model;

public class AuthResponse {
    private String accessToken;
    private String refreshToken;
    private String email;
    private String name;

    public AuthResponse(String accessToken, String refreshToken, String email, String name) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.email = email;
        this.name = name;
    }

    public String getAccessToken() { return accessToken; }
    public String getRefreshToken() { return refreshToken; }
    public String getEmail() { return email; }
    public String getName() { return name; }
}
