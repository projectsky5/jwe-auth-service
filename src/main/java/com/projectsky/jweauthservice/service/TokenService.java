package com.projectsky.jweauthservice.service;

import com.nimbusds.jwt.JWTClaimsSet;

import java.time.Instant;

public interface TokenService {

    String generateToken(String username, String role, Instant expiresAt);

    JWTClaimsSet decryptAndVerify(String token);

    void revokeToken();

    boolean isTokenValid(JWTClaimsSet claims);

    String extractJti(String token);

    Instant extractExpiration(String token);


}


