import subprocess

password = "admin123"

def run_command(user_input):
    subprocess.call(user_input, shell=True)

eval("print('Hello')")