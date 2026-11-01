from scanner.analysis.ast_parser import analyze_code_string

test_code = '''
import os
import pickle

password = "123456"

eval("2 + 2")

os.system("echo hello")

query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

data = pickle.loads(user_input)

open("folder/" + filename)
'''

results = analyze_code_string(test_code)

for result in results:
    print(result)