
import requests
import ssl
import socket
import certifi

from urllib.parse import urlparse
from datetime import datetime, timezone


# ==========================================
# FUNCTION 1: SECURITY HEADER AUDIT
# ==========================================

def check_security_headers(response):

    security_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]

    present_count = 0
    missing_headers = []

    print("\nSECURITY HEADER AUDIT")
    print("-----------------------------")

    for header in security_headers:

        if header in response.headers:
            print(header, ": PRESENT")
            present_count += 1

        else:
            print(header, ": MISSING")
            missing_headers.append(header)

    total_headers = len(security_headers)
    security_score = (present_count / total_headers) * 100

    print("\nSECURITY SCORE")
    print("-----------------------------")
    print("Headers Present:", present_count, "/", total_headers)
    print("Security Score:", security_score, "%")

    return missing_headers, security_score


# ==========================================
# FUNCTION 2: FINAL SECURITY AUDIT REPORT
# ==========================================

def generate_report(url, status_code, security_score,
                    missing_headers, certificate_status,
                    days_remaining):

    print("\n======================================")
    print("       FINAL SECURITY AUDIT REPORT")
    print("======================================")

    print("Website:", url)
    print("HTTP Status Code:", status_code)

    print("\nSECURITY HEADER SUMMARY")
    print("-----------------------------")
    print("Security Score:", security_score, "%")
    print("Missing Headers:", len(missing_headers))

    print("\nTLS CERTIFICATE SUMMARY")
    print("-----------------------------")
    print("Certificate Status:", certificate_status)

    if days_remaining is not None:
        print("Days Remaining:", days_remaining)
    else:
        print("Days Remaining: Not applicable")

    print("======================================")


# ==========================================
# MAIN PROGRAM
# ==========================================

# Website URL

# Get website URL from the user
url = input("Enter website URL: ").strip()

# Add HTTPS if protocol is missing
if not url.startswith(("http://", "https://")):
    url = "https://" + url

# Parse the URL
parsed_url = urlparse(url)

# Validate URL
if (
    parsed_url.scheme not in ("http", "https")
    or not parsed_url.hostname
    or "." not in parsed_url.hostname
    or " " in parsed_url.hostname
):
    print("Invalid URL. Please enter a valid website address.")
    exit()

print("Valid URL:", url)


# Send HTTP GET request
try:
    response = requests.get(url, timeout=10)

    print("Website:", url)
    print("Status Code:", response.status_code)

except requests.exceptions.Timeout:
    print("Error: Website connection timed out.")
    exit()

except requests.exceptions.ConnectionError:
    print("Error: Unable to connect to the website.")
    exit()

except requests.exceptions.RequestException as e:
    print("Request Error:", e)
    exit()


# ==========================================
# SECURITY HEADER AUDIT
# ==========================================

missing_headers, security_score = check_security_headers(response)


# ==========================================
# SECURITY RECOMMENDATIONS
# ==========================================

print("\nSECURITY RECOMMENDATIONS")
print("-----------------------------")

recommendations = {
    "Content-Security-Policy":
        "Configure a suitable Content Security Policy to help prevent XSS attacks.",

    "Strict-Transport-Security":
        "Enable HSTS to ensure browsers use HTTPS.",

    "X-Frame-Options":
        "Configure frame restrictions to help prevent clickjacking.",

    "X-Content-Type-Options":
        "Set this header to nosniff to prevent MIME-type sniffing.",

    "Referrer-Policy":
        "Configure an appropriate Referrer Policy to control referrer information."
}

for header in missing_headers:
    print("-", header)
    print("  Recommendation:", recommendations[header])



# ==========================================
# TLS CERTIFICATE INSPECTION
# ==========================================

print("\nTLS CERTIFICATE INSPECTION")
print("-----------------------------")

certificate_status = "NOT CHECKED"
days_remaining = None

hostname = urlparse(url).hostname

try:

    context = ssl.create_default_context(cafile=certifi.where())

    with socket.create_connection((hostname, 443), timeout=10) as sock:

        with context.wrap_socket(sock, server_hostname=hostname) as secure_socket:

            certificate = secure_socket.getpeercert()

            print("Connected to:", hostname)
            print("Certificate retrieved successfully!")

            # Extract certificate information
            subject = certificate.get("subject")
            issuer = certificate.get("issuer")

            valid_from = certificate.get("notBefore")
            valid_until = certificate.get("notAfter")

            # Convert dates into datetime objects
            valid_from_date = datetime.strptime(
                valid_from, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

            valid_until_date = datetime.strptime(
                valid_until, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

            current_time = datetime.now(timezone.utc)

            # Check certificate validity
            print("\nCERTIFICATE VALIDITY")
            print("-----------------------------")

            if current_time < valid_from_date:
                certificate_status = "NOT YET VALID"

            elif current_time > valid_until_date:
                certificate_status = "EXPIRED"

            else:
                certificate_status = "VALID"

            print("Status:", certificate_status)

            # Display certificate details
            print("\nCERTIFICATE DETAILS")
            print("-----------------------------")

            print("Subject:", subject)
            print("Issuer:", issuer)
            print("Valid From:", valid_from)
            print("Valid Until:", valid_until)

            # Calculate remaining days
            if certificate_status == "VALID":

                days_remaining = (valid_until_date - current_time).days

                print("Days Remaining:", days_remaining)

                if days_remaining <= 7:
                    print("WARNING: Certificate expires soon!")

                elif days_remaining <= 30:
                    print("NOTICE: Certificate expires within 30 days.")

                else:
                    print("Certificate expiry is not approaching.")


except ssl.SSLCertVerificationError:

    certificate_status = "CERTIFICATE VERIFICATION FAILED"
    print("TLS Error: Certificate verification failed.")

except socket.timeout:

    certificate_status = "CONNECTION TIMEOUT"
    print("TLS Error: Connection timed out.")

except ssl.SSLError:

    certificate_status = "TLS ERROR"
    print("TLS Error: Secure connection could not be established.")

except OSError as e:

    certificate_status = "CONNECTION ERROR"
    print("TLS Connection Error:", e)



# ==========================================
# GENERATE FINAL REPORT
# ==========================================

generate_report(
    url,
    response.status_code,
    security_score,
    missing_headers,
    certificate_status,
    days_remaining
)
