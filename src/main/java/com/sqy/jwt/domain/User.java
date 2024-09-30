package com.sqy.jwt.domain;

import java.util.*;

public record User(
    Long id,
    String username,
    String encodedPassword,
    List<String> roles
) {
}
