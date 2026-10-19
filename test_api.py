import requests

url = "http://127.0.0.1:8000/api/scan-code/"
payload = {
    "code": "def test():\n    eval('1+1')\n    password = '12345'"
}

response = requests.post(url, json=payload)
print("Status Code:", response.status_code)
print("Response JSON:")
print(response.json())