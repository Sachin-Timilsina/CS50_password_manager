CREATE TABLE IF NOT EXISTS Users (
    user_id INT PRIMARY KEY, 
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS Accounts (
    account_id INT PRIMARY KEY,
    user_id INT,
    website_url VARCHAR(255),
    username VARCHAR(255),
    encrypted_pw VARCHAR(255),
    encryption_iv VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES Users(user_id)
);