import requests

r = requests.post('http://localhost:3000/rest/user/login', json={'email': "test2@test.com", 'password': 'password'})
token = r.json()['authentication']['token']
r2 = requests.get('http://localhost:3000/rest/user/authentication-details/', headers={'Authorization': 'Bearer ' + token})
print('Details:', r2.status_code, r2.text)
