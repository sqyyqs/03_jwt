package com.sqy.jwt.service.mapper;

import com.sqy.jwt.domain.User;
import com.sqy.jwt.dto.UserDto;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {

    public UserDto toDto(User user) {
        return new UserDto(user.username(), user.roles());
    }
}
