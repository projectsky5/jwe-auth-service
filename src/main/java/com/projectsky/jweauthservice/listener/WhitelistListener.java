package com.projectsky.jweauthservice.listener;

import com.projectsky.jweauthservice.event.TokenIssuedEvent;
import com.projectsky.jweauthservice.event.TokenRevokedEvent;
import com.projectsky.jweauthservice.model.TokenWhitelist;
import com.projectsky.jweauthservice.repository.TokenWhitelistRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@RequiredArgsConstructor
public class WhitelistListener {

    private final TokenWhitelistRepository repository;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onTokenIssued(TokenIssuedEvent event) {
        repository.save(new TokenWhitelist(event.jti(), event.expiresAt()));
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onTokenRevoked(TokenRevokedEvent event) {
        repository.deleteById(event.jti());
    }
}
