DROP TABLE IF EXISTS user;
CREATE TABLE user (
    id   bigint NOT NULL AUTO_INCREMENT,
    login_name varchar(500) NOT NULL,
    password varchar(500) NOT NULL,
    last_login datetime DEFAULT NULL,
    account_expired tinyint(1) DEFAULT FALSE,
    account_locked tinyint(1) DEFAULT FALSE,
    credentials_expired tinyint(1) DEFAULT FALSE,
    enabled tinyint(1) DEFAULT FALSE,
    created_by bigint DEFAULT NULL,
    created_name varchar(500) DEFAULT NULL,
    created_ts datetime DEFAULT NULL,
    last_modified_by bigint DEFAULT NULL,
    last_modified_name varchar(500) DEFAULT NULL,
    last_modified_ts datetime DEFAULT NULL,
    `version` INT(11) DEFAULT '0',
    PRIMARY KEY (id),
    CONSTRAINT UC_USER UNIQUE (login_name)
);
INSERT INTO user (login_name, password,  created_by,created_name,created_ts) VALUES ('first', 'first',  1,'test',CURDATE()); 
INSERT INTO user (login_name, password,  created_by,created_name,created_ts) VALUES ('second', 'second',  1,'test',CURDATE()); 
INSERT INTO user (login_name, password,  created_by,created_name,created_ts) VALUES ('admin', 'admin@123', 1,'test',CURDATE());

create table authorities (
    id   bigint NOT NULL AUTO_INCREMENT,
    login_id bigint not null,
    authority varchar(50) not null,
    PRIMARY KEY (id),
    constraint fk_authorities_login_id foreign key(login_id) references user(id) 
);
create unique index ix_auth_login_id on authorities (login_id,authority); 

INSERT INTO authorities (login_id,authority) SELECT id ,'ROLE_USER' FROM user WHERE login_name='first';
INSERT INTO authorities (login_id,authority) SELECT id ,'ROLE_USER' FROM user WHERE login_name='second';
INSERT INTO authorities (login_id,authority) SELECT id ,'ROLE_ADMIN' FROM user WHERE login_name='admin';



