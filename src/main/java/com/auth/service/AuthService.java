package com.auth.service;

import com.auth.dto.request.LoginRequestDTO;
import com.auth.dto.request.SignUpRequestDTO;
import org.springframework.http.ResponseEntity;

public interface AuthService {
    String ROLE_ADMIN = "admin";
    String ROLE_MODERATOR = "mod";

    ResponseEntity authenticateUser(LoginRequestDTO loginRequestDTO);

    ResponseEntity registerUser(SignUpRequestDTO signUpRequestDTO);
}
