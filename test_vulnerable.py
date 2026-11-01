import hashlib

password = "123456"
hashed = hashlib.md5(password.encode()).hexdigest()

print(hashed)