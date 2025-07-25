package com.projectsky.jweauthservice.service;

import com.projectsky.jweauthservice.model.User;

public interface UserService {

    User getUserByUsername(String username);
}
