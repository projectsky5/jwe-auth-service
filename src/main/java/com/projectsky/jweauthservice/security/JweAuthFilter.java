package com.projectsky.jweauthservice.security;

import com.nimbusds.jwt.JWTClaimsSet;
import com.projectsky.jweauthservice.exception.InvalidTokenException;
import com.projectsky.jweauthservice.model.User;
import com.projectsky.jweauthservice.service.TokenService;
import com.projectsky.jweauthservice.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JweAuthFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);

        // Расшифровка + проверка подписи + claims
        JWTClaimsSet claims = tokenService.decryptAndVerify(token);

        // Проверка наличия токена в whitelist
        if (!tokenService.isTokenValid(claims)) {
            throw new InvalidTokenException("Token is not exists or revoked");
        }

        String username = claims.getSubject();
        User user = userService.getUserByUsername(username);

        Map<String, Object> details = new HashMap<>(); // Создание кастомного Details для Authentication
        details.put("jti", claims.getJWTID()); // Вложение jti в Details

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

        authentication.setDetails(details); // Установка в Authentication кастомных Details

        SecurityContextHolder.getContext().setAuthentication(authentication); // Сохраняем для текущего юзера Authentication с кастомными Details

        filterChain.doFilter(request, response);
    }
}
