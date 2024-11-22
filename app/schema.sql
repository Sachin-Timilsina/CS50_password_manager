-- Create users table if already not existing
CREATE TABLE IF NOT EXISTS Users (
    user_id INTEGER PRIMARY KEY, 
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL
);

-- Create accounts table if already not existing
CREATE TABLE IF NOT EXISTS Accounts (
    account_id INTEGER PRIMARY KEY,
    user_id INTEGER,
    website_url VARCHAR(255),
    encrypted_pw VARCHAR(255),
    encryption_iv VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES Users(user_id)
);
