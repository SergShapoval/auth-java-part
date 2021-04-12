package com.auth.dto.response;

import com.auth.model.ERole;

import java.util.List;

public class JWTResponseDTO {
    private String token;
    private ERole type;
    private long id;
    private String username;
    private String email;
    private List<String> roles;

    public JWTResponseDTO() {
    }

    public JWTResponseDTO(String token, long id, String username, String email, List<String> roles) {
        this.token = token;
        this.id = id;
        this.username = username;
        this.email = email;
        this.roles = roles;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public ERole getType() {
        return type;
    }

    public void setType(ERole type) {
        this.type = type;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}
