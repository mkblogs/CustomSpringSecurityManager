DROP TABLE IF EXISTS account;
CREATE TABLE account (
    id   bigint NOT NULL AUTO_INCREMENT,
    account_name VARCHAR(500) NOT NULL,
    account_type VARCHAR(500) NOT NULL,
    amount decimal NOT NULL,
    created_by bigint DEFAULT NULL,
    created_name VARCHAR(500) DEFAULT NULL,
    created_ts datetime DEFAULT NULL,
    last_modified_by bigint DEFAULT NULL,
    last_modified_name VARCHAR(500) DEFAULT NULL,
    last_modified_ts datetime DEFAULT NULL,
    `version` INT(11) DEFAULT '0',
    PRIMARY KEY (id)
);
INSERT INTO account (account_name, account_type, amount, created_by,created_name,created_ts) VALUES ('first', 'Savings', 100, 1,'test',CURDATE()); 
INSERT INTO account (account_name, account_type, amount, created_by,created_name,created_ts) VALUES ('second', 'Savings', 100, 1,'test',CURDATE()); 
INSERT INTO account (account_name, account_type, amount, created_by,created_name,created_ts) VALUES ('third', 'Savings', 100, 1,'test',CURDATE()); 