package com.example.backend.model;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Entity
@Table(name = "users")

public class User {
    @Id
    @Column(length = 36)
    private String id = UUID.randomUUID().toString();

    private String language;

    @Column(unique = true, nullable = false)
    private String email;

    private String password;

    private String name;

    private String image;

    private String provider; // google, github, credentials

    @Column(name = "createdAt", nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();
}