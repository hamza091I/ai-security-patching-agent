import sqlite3


def get_user_data(username):
  conn = sqlite3.connect("database.db")
  cursor = conn.cursor()
  cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
  return cursor.fetchall()