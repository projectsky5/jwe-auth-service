package com.projectsky.jweauthservice.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "token_whitelist")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class TokenWhitelist {

    @Id
    private String jti; // ID JWE токена

    private Instant expiresAt;
}
