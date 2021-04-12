package com.auth.controller;

import com.auth.dao.RoleDAO;
import com.auth.dao.UserDAO;
import com.auth.dto.request.LoginRequestDTO;
import com.auth.dto.request.SignUpRequestDTO;
import com.auth.dto.response.JWTResponseDTO;
import com.auth.dto.response.MessageResponseDTO;
import com.auth.model.ERole;
import com.auth.model.Role;
import com.auth.model.User;
import com.auth.security.jwt.JWTUtils;
import com.auth.security.service.UserDetailsImpl;
import com.auth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private AuthService authService;
    private AuthenticationManager authenticationManager;
    private UserDAO userDAO;
    private RoleDAO roleDAO;
    private PasswordEncoder passwordEncoder;
    private JWTUtils jwtUtils;

    public AuthController(AuthService authService,
                          AuthenticationManager authenticationManager,
                          UserDAO userDAO,
                          RoleDAO roleDAO,
                          PasswordEncoder passwordEncoder,
                          JWTUtils jwtUtils) {
        this.authService = authService;
        this.authenticationManager = authenticationManager;
        this.userDAO = userDAO;
        this.roleDAO = roleDAO;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequestDTO loginRequestDTO) {
        return this.authService.authenticateUser(loginRequestDTO);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequestDTO signUpRequestDTO) {
        return this.authService.registerUser(signUpRequestDTO);
    }
}
