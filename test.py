import sqlite3

DATABASE = 'users.db'

def get_db():
    """Connect to the SQLite database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Allows row access by column name
    return conn

def get_tables():
    """Fetch and print all table names from the SQLite database."""
    conn = get_db()
    try:
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
        # Print the table names
        for table in tables:
            print(f"Table: {table['name']}")
    finally:
        conn.close()

def fetch_table_data(table_name):
    """Fetch and print all data from a specified table."""
    conn = get_db()
    try:
        rows = conn.execute(f"SELECT * FROM {table_name};").fetchall()
        # Print each row as a dictionary
        for row in rows:
            print(dict(row))
    except sqlite3.OperationalError as e:
        print(f"Error: {e}")
    finally:
        conn.close()

# Main Script Execution
if __name__ == "__main__":
    print("Listing all tables:")
    get_tables()

    print("\nFetching data from 'users' table:")
    fetch_table_data("users")
