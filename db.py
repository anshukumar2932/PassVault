import sqlite3

DATABASE = 'users.db'

def get_db():
    """Connect to the SQLite database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Allows row access by column name
    return conn

def init_db():
    """Initialize the database and create the users table if it doesn't exist."""
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def create_user(user, hashed_password):
    """Insert a new user into the database."""
    conn = get_db()
    conn.execute("INSERT INTO users (user, password) VALUES (?, ?)", (user, hashed_password))
    conn.commit()
    conn.close()

def get_user_by_userid(user):
    """Retrieve a user by email from the database."""
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE user = ?", (user,)).fetchone()
    conn.close()
    return user

def get_password(user):
    """Retrieve the password (or password hash) of a user by email or mobile from the database."""
    conn = get_db()
    try:
        # Execute the query to retrieve the user by email/mobile
        user_data = conn.execute("SELECT * FROM users WHERE user = ?", (user,)).fetchone()
        
        if user_data is None:
            return None  # User not found

        return True 
    except Exception as e:
        # Log the error for debugging purposes
        print(f"Error fetching password: {e}")
        return None
    finally:
        conn.close()
def update_password(user, new_password):
    # Update the password in the database
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("UPDATE users SET password=? WHERE user=?", (new_password, user))
    status = False
    if connection.commit():
        status = True
    cursor.close()
    return status
