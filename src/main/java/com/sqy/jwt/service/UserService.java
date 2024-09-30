package com.sqy.jwt.service;

import java.util.*;

import com.sqy.jwt.domain.User;

public interface UserService {
    User findUserByUsername(String username);
    boolean register(User user);
    List<String> findRolesByUsername(String username);
}
