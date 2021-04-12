package com.auth.service.impl;

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
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AuthServiceImpl implements AuthService {
    private AuthenticationManager authenticationManager;
    private JWTUtils jwtUtils;
    private UserDAO userDAO;
    private PasswordEncoder passwordEncoder;
    private RoleDAO roleDAO;

    public AuthServiceImpl(AuthenticationManager authenticationManager,
                           JWTUtils jwtUtils,
                           UserDAO userDAO,
                           PasswordEncoder passwordEncoder,
                           RoleDAO roleDAO) {
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.userDAO = userDAO;
        this.passwordEncoder = passwordEncoder;
        this.roleDAO = roleDAO;
    }

    @Override
    public ResponseEntity authenticateUser(LoginRequestDTO loginRequestDTO) {

        Authentication authentication = this.authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequestDTO.getUsername(), loginRequestDTO.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JWTResponseDTO(this.jwtUtils.generateJwtToken(authentication),
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @Override
    public ResponseEntity registerUser(SignUpRequestDTO signUpRequestDTO) {
        if (this.userDAO.existsByUsername(signUpRequestDTO.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponseDTO("Username is already taken in use"));
        }

        if (this.userDAO.existsByEmail(signUpRequestDTO.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponseDTO("Error: Email is already in use!"));
        }

        User user = new User(signUpRequestDTO.getUsername(),
                signUpRequestDTO.getEmail(),
                this.passwordEncoder.encode(signUpRequestDTO.getPassword()));

        Set<String> stringRoles = signUpRequestDTO.getRoles();
        Set<Role> roles = new HashSet<>();

        if (Objects.isNull(stringRoles)) {
            Role userRole = roleDAO.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Role is not found."));
            roles.add(userRole);
        } else {
            stringRoles.forEach(role -> {
                        switch (role) {
                            case ROLE_ADMIN -> {
                                Role adminRole = this.roleDAO.findByName(ERole.ROLE_ADMIN)
                                        .orElseThrow(() -> new RuntimeException("Role is not found."));
                                roles.add(adminRole);
                            }
                            case ROLE_MODERATOR -> {
                                Role modRole = this.roleDAO.findByName(ERole.ROLE_MODERATOR)
                                        .orElseThrow(() -> new RuntimeException("Role is not found."));
                                roles.add(modRole);
                            }
                            default -> {
                                Role userRole = this.roleDAO.findByName(ERole.ROLE_USER)
                                        .orElseThrow(() -> new RuntimeException("Role is not found."));
                                roles.add(userRole);
                            }
                        }
                    }
            );
            user.setRoles(roles);
            userDAO.save(user);
        }
        return ResponseEntity.ok(new MessageResponseDTO("User registered successfully!"));
    }
}
