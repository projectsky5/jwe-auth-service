package com.projectsky.jweauthservice.repository;

import com.projectsky.jweauthservice.model.TokenWhitelist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;

public interface TokenWhitelistRepository extends JpaRepository<TokenWhitelist, String> {

    @Modifying
    @Query("""
    DELETE FROM TokenWhitelist t
    WHERE t.expiresAt < :timestamp
    """)
    int deleteAllByExpiresAtBefore(@Param("timestamp") Instant timestamp);


}
