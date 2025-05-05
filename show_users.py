import sqlite3

with sqlite3.connect("users.db") as conn:
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    print(cursor.fetchall())