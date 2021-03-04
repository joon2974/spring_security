package com.example.security1.repository;

import com.example.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {

    // findBy는 규칙 -> Username 은 문법
    // select * from user where username = ? 쿼리가 호출됨
    public User findByUsername(String username);
}
