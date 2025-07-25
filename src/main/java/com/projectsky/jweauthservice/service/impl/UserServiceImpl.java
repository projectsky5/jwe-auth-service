package com.projectsky.jweauthservice.service.impl;

import com.projectsky.jweauthservice.exception.UserNotFoundException;
import com.projectsky.jweauthservice.model.User;
import com.projectsky.jweauthservice.repository.UserRepository;
import com.projectsky.jweauthservice.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
    }
}
