import sqlite3
import validators
import bcrypt
import base64
import os
from flask import Flask, g, jsonify, render_template, request, redirect, url_for, session
from utils import check_password_strength, derive_session_key, encrypt_password, decrypt_password
from dotenv import load_dotenv

load_dotenv() # take env variables from .env

app = Flask(__name__)

# Set secret key for app.
app.secret_key = os.getenv("SECRET_KEY")

# DB setup
DATABASE = 'password_manager.db'

# Get a connection to db
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row # Enable column access by name
    return g.db

# Close the db connection
@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

# Create tables if they don't exist
def init_db():
    with app.app_context():
        db = get_db()
        with open('schema.sql', 'r') as f:
            db.executescript(f.read())
        db.commit()

# Route to create the tables on the first run
@app.before_request
def init_db_once():
    init_db()

# Ensure responses are not cached by browser
@app.after_request
def after_request(response):
    response.headers['Cache-Control'] = "no-cache, no-store, must-revalidate"
    response.headers['Expires'] = 0
    response.headers['Pragma'] = "no-cache"
    return response


@app.route('/')
def home():
    # If logged in go to accounts page
    if 'user_id' in session:
        return redirect(url_for('accounts'))
    
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # If logged in go to accounts page
    if 'user_id' in session:
        return redirect(url_for('accounts'))

    if request.method == 'POST':
        # Get user email, password, confirm_password
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validate user input email, password
        if not email:
            return render_template("error.html",error_code=400,error_message="Please provide email!"),400
        # Valid email
        elif not validators.email(email):
            return render_template("error.html", error_code=400,error_message="Please provide valid email!"),400
        elif not password:
            return render_template("error.html",error_code=400,error_message="Please provide password!"),400
        # Check if strong password
        elif len(password) < 8:
            return render_template("error.html",error_code=400,error_message="Password should be at least 8 characters."),400
        elif not any(char.isdigit() for char in password):
            return render_template("error.html",error_code=400,error_message="Password should contain at least 1 digit."),400
        elif not any(char.isupper() for char in password):
            return render_template("error.html",error_code=400,error_message="Password should contain at least 1 upper case letter."),400
        elif not any(char.islower() for char in password):
            return render_template("error.html",error_code=400,error_message="Password should contain at least 1 lower case letter"),400
        elif not any(char in "!\\@#$%^&*(){}[]|/.;''?+=-`,><:" for char in password):
            return render_template("error.html",error_code=400,error_message="Password should contain at least 1 special character"),400
        # Check password and confirm_password is same
        elif password != confirm_password:
            return render_template("error.html",error_code=400,error_message="Password confirmation failed!"),400
        

        # Get list of email and if they already exists
        db = get_db()
        users = db.execute('SELECT email FROM Users').fetchall()

        # Convert rows to list of dictionaries
        users_list = [dict(user) for user in users]

        # Check if the email is already associated with the user
        for user in users_list:
            if user['email'] == email:
                return render_template('error.html',error_code=400,error_message="User already exists!"),400
            
        
        # Generate salt for hashing
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode(), salt)

        # Input data into table (Ready salt and password hash as strings)
        salt = base64.b64encode(salt).decode()
        password_hash = base64.b64encode(password_hash).decode()
        
        # Insert new user into users table
        db.execute(
            'INSERT INTO Users (email, password_hash, salt) VALUES(?, ?, ?)',
            [email, password_hash, salt]
        )
        db.commit()

        # After Successfully signing up go to log in page
        return redirect(url_for('login'))
    
    # Handle Get Request
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If logged in go to accounts page
    if 'user_id' in session and 'session_key' in session:
        return redirect(url_for('accounts'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # If empty fields inputted 
        if not email or not password:
            return render_template("error.html", error_code=400, error_message="Please provide email and password!"), 400

        # Check if user email is correct
        db = get_db()
        user = db.execute('SELECT * FROM Users WHERE email = ?', (email,)).fetchone()

        if not user:
            return render_template("error.html", error_code=400, error_message="Credentials do not match!"), 400

        salt = base64.b64decode(user['salt'])
        stored_password_hash = base64.b64decode(user['password_hash'])

        # Verify password
        user_password_hash = bcrypt.hashpw(password.encode(), salt)
        if user_password_hash != stored_password_hash:
            return render_template("error.html", error_code=400, error_message="Credentials do not match!"), 400

        # Derive a session key and store it in the session
        session_key = derive_session_key(password, salt)
        session['user_id'] = user['user_id']
        session['email'] = user['email']
        session['session_key'] = base64.b64encode(session_key).decode()  # Store as base64 string

        return redirect(url_for('accounts'))

    return render_template('login.html')

@app.route('/accounts', methods=['POST', 'GET'])
def accounts():
    # If not logged in go back to login
    if 'user_id' not in session or 'session_key' not in session:
        return redirect(url_for('login'))
    
    # Get session key
    session_key = base64.b64decode(session['session_key'])

    if request.method == 'POST':
        web_url = request.form['website-url']
        password = request.form['password']

        encrypted_password, iv = encrypt_password(session_key, password)

        db = get_db()
        db.execute(
            'INSERT INTO Accounts (user_id, website_url, encrypted_pw, encryption_iv) VALUES(?, ?, ?, ?)',
            [session['user_id'], web_url, encrypted_password, iv]
        )
        db.commit()
        return redirect(url_for('accounts'))

    db = get_db()
    accounts = db.execute("SELECT * FROM Accounts WHERE user_id = ?", (session["user_id"],)).fetchall()

    # Get list as list of dict
    accounts_list = [dict(account) for account in accounts]

    # Put decrypted password in list of dict
    for account in accounts_list:
        encrypted_pw = base64.b64decode(account['encrypted_pw'])
        encryption_iv = base64.b64decode(account['encryption_iv'])

        decrypted_pw = decrypt_password(session_key, encrypted_pw, encryption_iv)
        account['decrypted_pw'] = decrypted_pw
        del account['encrypted_pw']

    return render_template('accounts.html', accounts_list=accounts_list)

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()  # Clear the session
    return redirect(url_for('login'))  # Redirect to login page

@app.route('/deleteaccount/<int:account_id>', methods=['POST'])
def deleteaccount(account_id):
    # Go to login page cannot delete account
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()

    # Delete the related account from accounts
    db.execute('DELETE FROM Accounts WHERE account_id = ? AND user_id = ?', (account_id, session['user_id']))
    db.commit()

    return redirect(url_for('accounts'))

# Master password strength checking
@app.route('/check_password_strength', methods=['POST'])
def check_password():
    # AJAX to validate password"
    data = request.json
    password = data.get('password', '')
    feedback = check_password_strength(password)
    return jsonify(feedback)

if __name__ == "__main__":
    app.run(debug=True)
