
import requests

# Website URL
url = "https://example.com"

# Send HTTP GET request
response = requests.get(url, timeout=10)

# Display response status
print("Website:", url)
print("Status Code:", response.status_code)

# Display HTTP response headers
print("\nHTTP RESPONSE HEADERS")
print("-----------------------------")

for header, value in response.headers.items():
    print(header, ":", value)



# List of important security headers
security_headers = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

# Initialize the counter
present_count = 0

print("\nSECURITY HEADER AUDIT")
print("-----------------------------")

for header in security_headers:
    if header in response.headers:
        print(header, ": PRESENT")
        present_count += 1
    else:
        print(header, ": MISSING")

# Calculate security score
total_headers = len(security_headers)
security_score = (present_count / total_headers) * 100

print("\nSECURITY SCORE")
print("-----------------------------")
print("Headers Present:", present_count, "/", total_headers)
print("Security Score:", security_score, "%")
