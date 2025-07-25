package com.projectsky.jweauthservice.listener;

import com.projectsky.jweauthservice.event.TokenIssuedEvent;
import com.projectsky.jweauthservice.event.TokenRevokedEvent;
import com.projectsky.jweauthservice.service.redis.RedisTokenStore;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@RequiredArgsConstructor
public class RedisTokenListener {

    private final RedisTokenStore redis;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onTokenIssued(TokenIssuedEvent event) {
        redis.store(event.jti(), event.expiresAt());
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onTokenRevoked(TokenRevokedEvent event) {
        redis.remove(event.jti());
    }
}
