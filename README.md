# Password Manager
#### Video Demo:  <https://youtu.be/C0DU3rg1r4o>
## Description

## Description

**Password Manager** is a web app implemented using:

- **Frontend**: HTML, CSS, Bootstrap, AJAX, JQuery, and JavaScript  
- **Backend**: Python, Flask framework, Jinja, and SQLite as DBMS  

The main purpose of **Password Manager** is to provide users with a secure place to store their passwords. It helps manage and protect sensitive information securely and easily with its safety practices.  

Key Features:
- **Hashing**: Used to protect master passwords.  
- **Symmetric Encryption**: Ensures account passwords are stored securely.  

---

## File Structure

The application's file structure looks like this:

## File Structure

The application's file structure is organized as follows:

    - app
        - static
            - css
                - styles.css
            - js
                - scripts.js
            - error_image.jpg
            - favicon.ico
        - templates
            - accounts.html
            - base.html
            - error.html
            - home.html
            - login.html
            - signup.html
        - .env
        - app.py
        - password_manager.db
        - schema.sql
        - utils.py
    - README.md
    - requirements.txt


---

## Why Did I Choose This Folder Structure?

The **separation of concerns** principle guided this folder structure. It makes the application more organized, readable, and maintainable. Each file and folder has a clear purpose, so you always know where to look when making changes.

---

## Explaining Each File & Their Purpose

### **App Folder**

This folder houses all core files and subfolders such as static, templates, `.env`, database, and utility scripts.

---

#### **Static Folder**

This folder contains all static assets that do not change during the app's runtime.  

1. **CSS Folder**  
   - `styles.css`: Contains all custom styling for the web app, including:  
     - Body and layout styles  
     - Navigation bar  
     - Buttons and forms  
     - Cards and footers  
     - Password feedback styles  

2. **JS Folder**  
   - `scripts.js`: Includes additional JavaScript functions with AJAX and JQuery. Key functionalities include:  
     - **`toggleConfirmPassword()`**: Toggles password visibility in the confirm password field on the signup page.  
     - **`togglePassword()`**: Toggles password visibility for input fields on signup, login, and accounts pages.  
     - **`goBack()`**: Navigates the user back one page (like browser back).  
     - **Real-Time Password Validation**:  
       - Uses AJAX and JQuery for dynamic password strength feedback.  
       - Displays a list of messages to help users create stronger passwords.  
     - **`generateRandomPassword()`**: Generates a 16-character password with a mix of letters, numbers, and symbols.  

3. **Other Files**  
   - `error_image.jpg`: Displays when an error occurs or invalid input is provided.  
   - `favicon.ico`: Represents the app's favicon.  

---

#### **Templates Folder**

Contains all HTML template files for the web app, rendered with Jinja for dynamic content.  

1. **`base.html`**:  
   - The base template for all pages, loading CSS, JS, Bootstrap, JQuery, and icons.  
   - Defines the navbar and footer used in other templates.  

2. **`home.html`**:  
   - Welcome page with a button linking to the signup page.  

3. **`signup.html`**:  
   - Contains a form with:
     - Email input field  
     - Master password input with real-time validation  
     - Confirm password input with visibility toggle  
   - AJAX dynamically updates feedback messages for password strength.  

4. **`login.html`**:  
   - Includes fields for email and password with toggle visibility and a submit button.  

5. **`error.html`**:  
   - Displays error messages along with an error image and a "Go Back" button.  

6. **`accounts.html`**:  
   - Displays a table of stored accounts with the following features:
     - Add new account with a form.  
     - Generate a random password.  
     - Delete accounts.  
   - Dynamically populates account data using Jinja.  

---

#### **Other Files**

- **`.env`**: Stores the `secret_key` for encrypting Flask sessions.  
- **`app.py`**: The main application file handling routes, requests, and responses.  
- **`password_manager.db`**: SQLite database file for storing user and account data.  
- **`schema.sql`**: Defines the database schema for users and accounts tables.  
- **`utils.py`**: Contains helper functions like password encryption and decryption.

---

## Functions and Routes Overview

### **Database Management**

- **`get_db()`**: Connects to the SQLite database.  
- **`init_db()`**: Initializes the database if not already set up.  

### **Core Routes**

1. **`/`**:  
   - Redirects to the accounts page if the session is active.  
   - Renders `home.html` if the session is inactive.  

2. **`/signup`**:  
   - Handles user signup with password validation.  
   - Hashes the master password and stores it securely.  

3. **`/login`**:  
   - Authenticates users and starts a session.  

4. **`/accounts`**:  
   - Displays the user's stored accounts.  
   - Adds new accounts with encrypted passwords.  

5. **`/logout`**:  
   - Clears the session and redirects to login.  

6. **`/deleteaccount/<account_id>`**:  
   - Deletes the account with the specified ID.  

7. **`/check_password_strength`**:  
   - Validates passwords asynchronously via AJAX.  

---

## Utility Functions

- **Encryption & Decryption**  
  - `encrypt_password()`: Encrypts account passwords using AES.  
  - `decrypt_password()`: Decrypts encrypted passwords.  

- **Password Strength Checking**  
  - `check_password_strength()`: Validates password strength and provides feedback.  

- **Session Key Derivation**  
  - `derive_session_key()`: Generates a secure session key.  

---

## Requirements File

The `requirements.txt` includes all dependencies for the app. 
