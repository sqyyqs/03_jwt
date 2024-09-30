CREATE TABLE IF NOT EXISTS jwt_user
(
    user_id  bigserial primary key,
    username text unique,
    password text
);

CREATE TABLE IF NOT EXISTS user_roles
(
    user_id   bigint references jwt_user (user_id),
    role_name text,
    primary key (user_id, role_name)
);

CREATE TABLE IF NOT EXISTS revoked_token
(
    token_value text primary key,
    keep_until  timestamp not null
)
