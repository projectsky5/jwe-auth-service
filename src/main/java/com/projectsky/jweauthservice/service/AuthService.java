package com.projectsky.jweauthservice.service;

import com.projectsky.jweauthservice.dto.TokenDto;
import com.projectsky.jweauthservice.dto.request.LoginRequest;
import com.projectsky.jweauthservice.dto.request.RegisterRequest;

public interface AuthService {

    TokenDto toggleCurrentUserRole();

    TokenDto register(RegisterRequest request);

    TokenDto login(LoginRequest request);


}
