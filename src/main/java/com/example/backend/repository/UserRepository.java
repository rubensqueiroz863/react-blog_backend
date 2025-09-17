package com.example.backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.backend.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {
    // Buscar usuário pelo email
    Optional<User> findByEmail(String email);
}
