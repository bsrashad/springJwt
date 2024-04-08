package com.rashad.springJwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.rashad.springJwt.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByUsername(String username);
    Optional<User> findByUsernameAndPassword(String username, String password);
}
