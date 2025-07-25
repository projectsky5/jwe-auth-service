package com.projectsky.jweauthservice.service.impl;

import com.projectsky.jweauthservice.dto.TokenDto;
import com.projectsky.jweauthservice.dto.request.LoginRequest;
import com.projectsky.jweauthservice.dto.request.RegisterRequest;
import com.projectsky.jweauthservice.enums.Role;
import com.projectsky.jweauthservice.event.TokenIssuedEvent;
import com.projectsky.jweauthservice.event.TokenRevokedEvent;
import com.projectsky.jweauthservice.exception.UserAlreadyExistsException;
import com.projectsky.jweauthservice.exception.UserNotFoundException;
import com.projectsky.jweauthservice.model.User;
import com.projectsky.jweauthservice.repository.UserRepository;
import com.projectsky.jweauthservice.security.util.DetailsUtil;
import com.projectsky.jweauthservice.service.AuthService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final TokenServiceImpl tokenService;
    private final PasswordEncoder passwordEncoder;
    private final ApplicationEventPublisher publisher;

    @Value("${security.jwt.ttl-seconds:3600}")
    private long ttlSeconds;

    /**
     * Меняет роль пользователя свитчом
     * При смене роли:
     *  В БД сохраняется обновленный пользователь
     *  Отзывается прошлый токен
     *  Генерируется новый токен, заносится в белый список
     * */
    @Override
    @Transactional
    public TokenDto toggleCurrentUserRole() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()){
            throw new IllegalStateException("Authentication is not authenticated");
        }

        User user = (User) authentication.getPrincipal(); // Получение юзера

        Map<String, Object> details = DetailsUtil.getDetails(authentication); // Детали из Authentication

        String jti = (String) details.get("jti");

        Role newRole = user.getRole() == Role.USER ? Role.ADMIN : Role.USER; // свитч роли

        user.setRole(newRole);
        userRepository.save(user);

        publisher.publishEvent(new TokenRevokedEvent(jti));

        String token = tokenService.generateToken(
                user.getUsername(),
                newRole.getAuthority(),
                Instant.now().plusSeconds(ttlSeconds)
        );

        publisher.publishEvent(
                TokenIssuedEvent.builder()
                        .jti(tokenService.extractJti(token))
                        .expiresAt(tokenService.extractExpiration(token))
                        .username(user.getUsername())
                        .build());

        return new TokenDto(token);
    }

    @Override
    @Transactional
    public TokenDto register(RegisterRequest request){
        if(userRepository.existsByUsername(request.username())){
            throw new UserAlreadyExistsException("User already exists");
        }

        User user = User.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .role(Role.USER) // по умолчанию USER
                .build();
        userRepository.save(user);

        String token = tokenService.generateToken(
                request.username(),
                user.getRole().getAuthority(),
                Instant.now().plusSeconds(ttlSeconds)
        );

        publisher.publishEvent(
                TokenIssuedEvent.builder()
                        .jti(tokenService.extractJti(token))
                        .expiresAt(tokenService.extractExpiration(token))
                        .username(user.getUsername())
                        .build());

        return new TokenDto(token);
    }

    @Override
    @Transactional
    public TokenDto login(LoginRequest request) {
        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new BadCredentialsException("Invalid credentials");
        }

        String token = tokenService.generateToken(user.getUsername(),
                user.getRole().getAuthority(),
                Instant.now().plusSeconds(ttlSeconds));

        publisher.publishEvent(
                TokenIssuedEvent.builder()
                        .jti(tokenService.extractJti(token))
                        .expiresAt(tokenService.extractExpiration(token))
                        .username(user.getUsername())
                        .build());

        return new TokenDto(token);
    }
}
