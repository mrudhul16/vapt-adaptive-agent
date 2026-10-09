import requests

r = requests.post('http://localhost:3000/api/Users', json={"email": "test2@test.com", "password": "password", "passwordRepeat": "password", "securityQuestion": {"id": 1, "question": "Name of your favorite pet?", "createdAt": "2026-10-09T05:02:18.913Z", "updatedAt": "2026-10-09T05:02:18.913Z"}, "securityAnswer": "dog"})
print('Register:', r.status_code)

r = requests.post('http://localhost:3000/rest/user/login', json={'email': "test2@test.com", 'password': 'password'})
print('Login:', r.status_code, r.text)

try:
    token = r.json()['authentication']['token']
    r2 = requests.get('http://localhost:3000/rest/user/whoami', headers={'Authorization': 'Bearer ' + token})
    print('Whoami:', r2.status_code, r2.text)
except Exception as e:
    print(e)
