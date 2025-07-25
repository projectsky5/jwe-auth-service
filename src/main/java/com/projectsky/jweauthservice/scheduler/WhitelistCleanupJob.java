package com.projectsky.jweauthservice.scheduler;

import com.projectsky.jweauthservice.repository.TokenWhitelistRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Component
@RequiredArgsConstructor
public class WhitelistCleanupJob {

    private final TokenWhitelistRepository whitelistRepository;

    // Запускается каждый час
    @Scheduled(cron = "0 0 * * * *")
    @Transactional
    public void cleanupExpiredTokens() {
        Instant now = Instant.now();
        whitelistRepository.deleteAllByExpiresAtBefore(now);
    }
}
