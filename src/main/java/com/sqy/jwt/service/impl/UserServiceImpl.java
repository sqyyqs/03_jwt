package com.sqy.jwt.service.impl;

import java.util.*;

import com.sqy.jwt.domain.User;
import com.sqy.jwt.repository.RoleRepository;
import com.sqy.jwt.repository.UserRepository;
import com.sqy.jwt.service.UserService;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public UserServiceImpl(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @Override
    public User findUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public boolean register(User user) {
        Long userId = userRepository.createUser(user);
        if (userId == null) {
            return false;
        }
        roleRepository.saveRoles(user.roles(), userId);
        return true;
    }

    @Override
    public List<String> findRolesByUsername(String login) {
        return roleRepository.findRolesByLogin(login);
    }
}
