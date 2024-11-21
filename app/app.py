import sqlite3
import validators
import bcrypt
import base64
import os
from flask import Flask, g, jsonify, render_template, request, redirect, url_for, session
from utils import check_password_strength
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

    # If logged in go to accounts page
    if 'user_id' in session:
        return redirect(url_for('accounts'))
    
    # Handle Get Request
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get user email, password
        email = request.form['email']
        password = request.form['password']

        # Validate user input email, password
        if not email:
            return render_template("error.html",error_code=400,error_message="Please provide email!"),400
        elif not password:
            return render_template("error.html",error_code=400,error_message="Please provide password!"),400
        
        # Check if the user exists with that email.
        db = get_db()
        user = db.execute('SELECT * FROM Users WHERE email = ?', (email,)).fetchone()

        if not user:
            return render_template("error.html",error_code=400,error_message="Credentials do not match!"),400
        
        base64_salt = user['salt']
        base64_password_hash = user['password_hash']

        # Decode salt and hash to be in byte format
        salt = base64.b64decode(base64_salt)
        stored_password_hash = base64.b64decode(base64_password_hash)

        # Rehash user input password with the stored salt
        user_password_hash = bcrypt.hashpw(password.encode(), salt)

        password_match = user_password_hash == stored_password_hash

        if not password_match:
            return render_template("error.html",error_code=400,error_message="Credentials do not match!")
        
        # email and password matched start session and show the page of accounts
        # store the user_id in session
        session['user_id'] = user['user_id']
        session['email'] = user['email']
        session['password'] = password # NOT A GOOD PRACTICE BUT let's go with it! Don't punish me cyber security gods

        return redirect(url_for('accounts.html'))
    
    # If logged in go to accounts page
    if 'user_id' in session:
        return redirect(url_for('accounts'))

    return render_template('login.html')

@app.route('/accounts', methods=['POST', 'GET'])
def accounts():
    if request.method == 'POST':
        pass
    # Go back to login if not logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Render the accounts page.
    return render_template('accounts.html')

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
