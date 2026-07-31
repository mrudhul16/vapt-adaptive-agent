import requests

response = requests.get("http://localhost:3000")
print("Status code:", response.status_code)
print("\nHeaders:")
for key, value in response.headers.items():
    print(f"  {key}: {value}")