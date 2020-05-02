import requests
ad = requests.get('http://localhost:5000/peers').json()
print(ad)