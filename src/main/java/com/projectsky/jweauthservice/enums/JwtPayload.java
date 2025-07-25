package com.projectsky.jweauthservice.enums;

import lombok.Getter;

public enum JwtPayload {

    ROLE("role");

    @Getter
    private final String value;

    JwtPayload(String value) {
        this.value = value;
    }
}
