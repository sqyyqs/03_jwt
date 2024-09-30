package com.sqy.jwt.dto;

import java.util.*;

public record UserDto(
    String username,
    List<String> roles
) {
}