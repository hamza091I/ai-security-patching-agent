"""Manual API smoke test. Run the server first: python manage.py runserver."""
import requests
if __name__ == '__main__':
    response=requests.post('http://127.0.0.1:8000/api/scan/',json={'code':'value = eval(user_input)','filename':'sample.py'},timeout=10)
    print(response.status_code); print(response.json())
