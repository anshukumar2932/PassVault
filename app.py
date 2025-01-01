from flask import Flask, render_template, request, redirect, url_for, session, flash,get_flashed_messages
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from db import init_db, create_user, get_user_by_userid, get_user_data, update_password, add_user_data
from datetime import timedelta


app = Flask(__name__)
app.secret_key = "supersecretkey"
app.permanent_session_lifetime = timedelta(minutes=30)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize the database
init_db()

# Reset session for password recovery
reset_session = {}

# User model
class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

@login_manager.user_loader
def load_user(user_id):
    user_data = get_user_by_userid(user_id)
    return User(user_data['user']) if user_data else None

def redirect_authenticated_user():
    if current_user.is_authenticated:
        return redirect(url_for('protected', username=current_user.id))

@app.route('/')
def home():
    return redirect_authenticated_user() or redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    session.clear()
    if request.method == 'POST':
        user = request.form['user']
        password = request.form['password']

        user_data = get_user_by_userid(user)
        if user_data and check_password_hash(user_data['password'], password):
            login_user(User(user))
            session.permanent = True
            return redirect(url_for('protected', username=current_user.id))

        flash("Invalid credentials")
    return render_template('login_signup.html', mode="login")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('protected', username=current_user.id))

    if request.method == 'POST':
        user = request.form['user']
        password = request.form['password']

        if get_user_by_userid(user):
            flash("User already exists")
        else:
            create_user(user, generate_password_hash(password, method='pbkdf2:sha256'))
            flash("Signup successful. Please log in.")
            return redirect(url_for('login'))

    return render_template('login_signup.html', mode="signup")

@app.route('/protected/<username>')
@login_required
def protected(username):
    if username != current_user.id:
        return "Unauthorized", 403
    return render_template('index.html', username=current_user.id)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Logged out successfully")
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        new_password = request.form.get('new_password')

        if username and not new_password:
            if not get_user_by_userid(username):
                flash("User does not exist!")
            else:
                reset_session['user'] = username
                return render_template('forgot_password.html', email_form=False)

        elif new_password and reset_session.get('user'):
            update_password(reset_session.pop('user'), generate_password_hash(new_password, method='pbkdf2:sha256'))
            flash("Password updated successfully!")
            return redirect(url_for('login'))

        flash("An error occurred. Please try again.")

    return render_template('forgot_password.html', email_form=True)

@app.route('/protected/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    if request.method == 'POST':
        user = request.form.get('user')
        password = request.form.get('password')
        result = add_user_data(current_user.id, user, password)
        flash("Successfully added data" if result else "An error occurred.")

    return render_template('index.html', username=current_user.id, mode="Add")

@app.route('/protected/view_password', methods=['GET'])
@login_required
def view_password():
    credentials = get_user_data(current_user.id)
    return render_template('index.html', username=current_user.id, mode="View", credentials=credentials)

if __name__ == "__main__":
    app.run(debug=True)
