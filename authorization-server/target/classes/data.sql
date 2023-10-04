INSERT INTO users(username, password, enabled)
    VALUES('user', '{noop}password', true);

INSERT INTO users(username, password, enabled)
    VALUES('admin', '{noop}password', true);


 INSERT INTO roles(id, role)
     VALUES(1, 'ROLE_USER');

 INSERT INTO roles(id, role)
     VALUES(2, 'ROLE_ADMIN');