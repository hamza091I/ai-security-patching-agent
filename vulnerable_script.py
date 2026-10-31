import os
DB_USER = "admin"
DB_password = os.getenv("DB_PASSWORD")

def connect_database():
  return connect(user=DB_USER, password=DB_PASSWORD)