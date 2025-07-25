package com.projectsky.jweauthservice.controller;

import com.projectsky.jweauthservice.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/token")
@RequiredArgsConstructor
public class TokenController {

    private final TokenService tokenService;

    @PostMapping("/revoke")
    public ResponseEntity<Void> revoke() {
        tokenService.revokeToken();
        return ResponseEntity.noContent().build();
    }
}
