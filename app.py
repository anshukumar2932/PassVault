from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from db import init_db, create_user, get_user_by_userid, get_user_data, update_password,add_user_data
from datetime import timedelta

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Set the session lifetime (e.g., 15 minutes)
app.permanent_session_lifetime = timedelta(minutes=15)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

reset_session = {}

# Initialize the database (create tables if they don't exist)
init_db()

# User model
class User(UserMixin):
    def __init__(self, user):
        self.id = user

@login_manager.user_loader
def load_user(user_id):
    user_data = get_user_by_userid(user_id)
    if user_data:
        return User(user_data['user'])
    return None

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('protected', username=current_user.id))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    session.clear()
    if request.method == 'POST':
        user = request.form['user']
        password = request.form['password']
        
        user_data = get_user_by_userid(user)
        if user_data and check_password_hash(user_data['password'], password):
            user = User(user)
            login_user(user)
            session.permanent = True  # Enable permanent session
            return redirect(url_for('protected', username=current_user.id))
        
        flash("Invalid credentials")
        return render_template('login_signup.html', mode="login")
    
    return render_template('login_signup.html', mode="login")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if not current_user.is_authenticated:
        if request.method == 'POST':
            user = request.form['user']
            password = request.form['password']
            
            user_data = get_user_by_userid(user)
            if user_data:
                flash("User already exists")
                return render_template('login_signup.html', mode="signup")
            
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            create_user(user, hashed_password)
            flash("Signup successful. Please log in.")
            return redirect(url_for('login'))
        return render_template('login_signup.html', mode="signup")
    else:
        return redirect(url_for('protected', username=current_user.id))
    

@app.route('/protected/<username>')
@login_required
def protected(username):
    if username != current_user.id:
        return "Unauthorized", 403
    return render_template('index.html', username=current_user.id)

@app.route('/logout',methods=['POST'])
@login_required
def logout():
    logout_user()
    session.clear()  # Clear session data properly
    flash("Logged out successfully")  # Flash logout success message
    return redirect(url_for('login'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    email_form = True

    if request.method == 'POST':
        username = request.form.get('username')
        new_password = request.form.get('new_password')

        if username and not new_password:
            check_user = get_user_by_userid(username)
            if not check_user:
                flash("User does not exist!")
                return redirect(url_for('forgot_password'))
            
            reset_session['user'] = username
            email_form = False
            return render_template('forgot_password.html', email_form=email_form)

        if reset_session.get('user') and new_password:
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            update_password(reset_session['user'], hashed_password)
            flash("Password updated successfully!")
            reset_session.clear()
            return redirect(url_for('login'))
        
        flash("Some error occurred!")
        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html', email_form=email_form)
@app.route('/protected/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    if request.method == 'POST':
        user = request.form.get('user')
        password = request.form.get('password')
        result=add_user_data(current_user.id, user, password)
        if result:
            flash("Succesfully data added")
        else:
            flash(result)
    return render_template('index.html',username=current_user.id,mode="Add")

@app.route('/protected/view_password', methods=['GET'])
@login_required
def view_password():
    credentials = get_user_data(current_user.id)
    return render_template('index.html', username=current_user.id, mode="View", credentials=credentials)

if __name__ == "__main__":
    app.run(debug=True)
