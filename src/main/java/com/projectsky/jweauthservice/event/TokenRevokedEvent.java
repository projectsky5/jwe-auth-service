package com.projectsky.jweauthservice.event;

public record TokenRevokedEvent(
        String jti
) {
}
