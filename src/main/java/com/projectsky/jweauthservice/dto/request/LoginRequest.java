package com.projectsky.jweauthservice.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record LoginRequest(

        @NotBlank(message = "Username не должен быть пустым")
        @Size(min = 6, max = 12, message = "Username должен быть от 6 до 12 символов")
        @Pattern(regexp = "^[A-Za-z0-9.]+$", message = "Username может содержать только латинские буквы, цифры и точку")
        String username,

        @NotBlank
        String password
) {
}
