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
import java.util.Locale;

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

            if (attrs.containsKey("sub")) { // Apenas Google
                String email = (String) attrs.get("email");

                // Detecta idioma do navegador (ex: "pt-BR", "en-US", etc.)
                Locale locale = request.getLocale();
                String languageTag = locale.toLanguageTag();

                var user = userRepo.findByEmail(email).orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setName((String) attrs.get("name"));
                    newUser.setProvider("google");
                    newUser.setLanguage(languageTag); // salva o idioma ao criar
                    return userRepo.save(newUser);
                });

                // Atualiza se mudou
                if (user.getLanguage() == null || !user.getLanguage().equals(languageTag)) {
                    user.setLanguage(languageTag);
                    userRepo.save(user);
                }

                String token = jwtService.generateToken(user);

                // Retorna o token e idioma
                response.setContentType("application/json");
                response.getWriter().write(
                        "{\"token\":\"" + token + "\"," +
                        "\"email\":\"" + user.getEmail() + "\"," +
                        "\"name\":\"" + user.getName() + "\"," +
                        "\"language\":\"" + user.getLanguage() + "\"}"
                );
                response.getWriter().flush();
            }
        }
    }
}