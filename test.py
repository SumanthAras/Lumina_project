import requests

try:
    response = requests.get('https://www.google.com')
    print("Internet working. Status code:", response.status_code)
except Exception as e:
    print("Internet issue:", e)
