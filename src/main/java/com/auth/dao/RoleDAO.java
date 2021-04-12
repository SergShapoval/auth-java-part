package com.auth.dao;

import com.auth.model.ERole;
import com.auth.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleDAO extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
