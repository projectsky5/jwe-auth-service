package com.projectsky.jweauthservice.controller;

import com.projectsky.jweauthservice.dto.TokenDto;
import com.projectsky.jweauthservice.dto.request.LoginRequest;
import com.projectsky.jweauthservice.dto.request.RegisterRequest;
import com.projectsky.jweauthservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<TokenDto> register(
            @RequestBody @Valid RegisterRequest request
    ) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenDto> login(
            @RequestBody @Valid LoginRequest request
    ){
        return ResponseEntity.ok(authService.login(request));
    }

    @PatchMapping("/role/toggle")
    public ResponseEntity<TokenDto> toggleRole(){
        return ResponseEntity.ok(authService.toggleCurrentUserRole());
    }
}