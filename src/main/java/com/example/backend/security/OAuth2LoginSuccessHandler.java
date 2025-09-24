package com.example.backend.security;

import com.example.backend.model.User;
import com.example.backend.repository.UserRepository;
import com.example.backend.service.JwtService;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepo;

    public OAuth2LoginSuccessHandler(JwtService jwtService, UserRepository userRepo) {
        this.jwtService = jwtService;
        this.userRepo = userRepo;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        if (authentication.getPrincipal() instanceof OAuth2User oAuth2User) {
            var attrs = oAuth2User.getAttributes();

            // Apenas Google
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

                // Retorna o token no corpo da resposta
                response.setContentType("application/json");
                response.getWriter().write("{\"token\":\"" + token + "\",\"email\":\"" + user.getEmail() + "\",\"name\":\"" + user.getName() + "\"}");
                response.getWriter().flush();
            }
        }
    }
}
