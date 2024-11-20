import sqlite3
from flask import Flask, g, jsonify, render_template, request
from utils import check_password_strength

app = Flask(__name__)

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

# Route to create the tables on the first run
@app.before_request
def before_request():
    init_db()


@app.route('/')
def home():
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
            return render_template("error.html",error_code=400,error_message="Please provide email!",),400
        elif not password:
            return render_template("error.html",error_code=400,error_message="Please provide password!",),400
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
            return render_template("error.html",error_code=400,error_message="Password confirmation failed!",),400
        
        # Input user email and hashed master password in db.
        # TODO: 
    # Handle Get Request
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')

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
