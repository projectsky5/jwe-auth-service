package com.projectsky.jweauthservice.service.redis;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

// In-memory белый список токенов
@Component
@RequiredArgsConstructor
public class RedisTokenStore {

    private final StringRedisTemplate redisTemplate;
    private static final String PREFIX = "jwt:whitelist:";

    // Добавление jti токена в Redis с TTL до истечения срока
    public void store(String jti, Instant expiresAt) {
        long ttlSeconds = Duration.between(Instant.now(), expiresAt).getSeconds();
        redisTemplate.opsForValue().set(PREFIX + jti, "1", ttlSeconds, TimeUnit.SECONDS);
    }

    // Проверка на существование jti и не истек ли он
    public boolean isValid(String jti, Instant tokenExp) {
        String value = redisTemplate.opsForValue().get(PREFIX + jti);
        return value != null && Instant.now().isBefore(tokenExp);
    }

    // Удаление для отзыва токена
    public void remove(String jti) {
        redisTemplate.delete(PREFIX + jti);
    }
}
