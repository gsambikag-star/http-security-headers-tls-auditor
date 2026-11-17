import requests
import ssl
import socket
import certifi

from urllib.parse import urlparse
from datetime import datetime, timezone


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


# TLS CERTIFICATE INSPECTION

print("\nTLS CERTIFICATE INSPECTION")
print("-----------------------------")

# Extract hostname from the website URL
hostname = urlparse(url).hostname

# Create a secure SSL context

context = ssl.create_default_context(cafile=certifi.where())

# Connect to the website
with socket.create_connection((hostname, 443), timeout=10) as sock:

    # Establish a secure TLS connection
    with context.wrap_socket(sock, server_hostname=hostname) as secure_socket:

        # Retrieve the website's certificate
        certificate = secure_socket.getpeercert()
        

        print("Connected to:", hostname)
        print("Certificate retrieved successfully!")


        # Extract certificate subject
        subject = certificate.get("subject")

        # Extract certificate issuer
        issuer = certificate.get("issuer")

        # Extract validity dates
        valid_from = certificate.get("notBefore")
        valid_until = certificate.get("notAfter")

        # Convert certificate dates into datetime objects
        valid_from_date = datetime.strptime(
            valid_from, "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        valid_until_date = datetime.strptime(
            valid_until, "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        # Get the current UTC time
        current_time = datetime.now(timezone.utc)

        # Check certificate validity
        print("\nCERTIFICATE VALIDITY")
        print("-----------------------------")

        if current_time < valid_from_date:
            print("Status: NOT YET VALID")

        elif current_time > valid_until_date:
            print("Status: EXPIRED")

        else:
            print("Status: VALID")


        # Display certificate information
        print("\nCERTIFICATE DETAILS")
        print("-----------------------------")

        print("Subject:", subject)
        print("Issuer:", issuer)
        print("Valid From:", valid_from)
        print("Valid Until:", valid_until)


        # Calculate remaining certificate validity
        if current_time <= valid_until_date:

            remaining_days = (valid_until_date - current_time).days

            print("Days Remaining:", remaining_days)

            if remaining_days <= 7:
                print("WARNING: Certificate expires soon!")

            elif remaining_days <= 30:
                print("NOTICE: Certificate expires within 30 days.")

            else:
                print("Certificate expiry is not approaching.")


