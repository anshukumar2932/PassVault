import sqlite3

DATABASE = 'users.db'

def get_db():
    """Connect to the SQLite database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Enables dictionary-like access to rows
    return conn

def init_db():
    """Initialize the database and create the users table if it doesn't exist."""
    try:
        with get_db() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user TEXT PRIMARY KEY,
                    password TEXT NOT NULL
                )
            ''')
            conn.commit()
    except Exception as e:
        print(f"Error initializing the database: {e}")

def create_user(user, hashed_password):
    """Insert a new user into the database and create a user-specific table."""
    try:
        with get_db() as conn:
            # Insert user into the main users table
            conn.execute("INSERT INTO users (user, password) VALUES (?, ?)", (user, hashed_password))
            
            # Create a user-specific table
            user_table_query = f'''
                CREATE TABLE IF NOT EXISTS "{user}" (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    userid TEXT NOT NULL,
                    password TEXT NOT NULL
                )
            '''
            conn.execute(user_table_query)
            conn.commit()
    except sqlite3.IntegrityError:
        raise ValueError("User already exists.")
    except Exception as e:
        print(f"Error creating user: {e}")
        raise

def get_user_by_userid(user):
    """Retrieve a user by ID from the database."""
    try:
        with get_db() as conn:
            user_data = conn.execute("SELECT * FROM users WHERE user = ?", (user,)).fetchone()
            return dict(user_data) if user_data else None
    except Exception as e:
        print(f"Error fetching user by user ID: {e}")
        return None

def update_password(user, new_password):
    """Update the user's password."""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password=? WHERE user=?", (new_password, user))
            conn.commit()
            return cursor.rowcount > 0  # True if a row was updated
    except Exception as e:
        print(f"Error updating password: {e}")
        return False

def add_user_data(user, userid, password):
    """Add data to the user's specific table."""
    try:
        with get_db() as conn:
            query = f'INSERT INTO "{user}" (userid, password) VALUES (?, ?)'
            conn.execute(query, (userid, password))
            conn.commit()
        return True
    except Exception as e:
        error=f"Error adding data for user {user}: {e}"
        print(error)
        return error

def get_user_data(user):
    """Retrieve all data from the user's specific table."""
    try:
        with get_db() as conn:
            query = f'SELECT * FROM "{user}"'
            data = conn.execute(query).fetchall()
            return [dict(row) for row in data]  # Convert rows to dictionary format
    except Exception as e:
        print(f"Error fetching data for user {user}: {e}")
        return None
