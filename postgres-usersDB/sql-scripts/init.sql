CREATE DATABASE users_db;
CREATE TABLE IF NOT EXISTS users
(
	user_id serial PRIMARY KEY,
	email VARCHAR( 100 ) UNIQUE NOT NULL,
	password_hash VARCHAR ( 100 ) NOT NULL,
	created_on VARCHAR ( 100 ) NOT NULL
);

CREATE TABLE IF NOT EXISTS relations
(
	relation_id serial PRIMARY KEY,
	follower INT NOT NULL,
	following INT NOT NULL,
	created_on VARCHAR ( 100 ) NOT NULL
);

INSERT INTO users (user_id, email, password_hash, created_on) VALUES (1, 'test@mail.com', 'password_hash', '2006-01-01 15:36:38');
INSERT INTO users (user_id, email, password_hash, created_on) VALUES (2, 'test2@mail.com', 'password_hash', '2006-01-01 15:36:39');
INSERT INTO relations (relation_id, follower, following, created_on) VALUES (1, 1, 2, '2006-01-01 15:36:38');
