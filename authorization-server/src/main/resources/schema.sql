DROP TABLE IF EXISTS authorities;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    username VARCHAR(100) NOT NULL PRIMARY KEY,
    password VARCHAR(159) NOT NULL,
    enabled boolean NOT NULL
);

CREATE TABLE authorities (
    username VARCHAR(100) NOT NULL REFERENCES users(username),
    authority VARCHAR(200) NOT NULL
);

--CREATE TABLE IF NOT EXISTS roles (
--    id LONG NOT NULL,
--    role VARCHAR(200) DEFAULT NULL,
--    FOREIGN KEY (id) REFERENCES users (id)
--);


