package com.projectsky.jweauthservice.event;

import lombok.Builder;

import java.time.Instant;

@Builder
public record TokenIssuedEvent(
        String jti,
        Instant expiresAt,
        String username
) {
}
