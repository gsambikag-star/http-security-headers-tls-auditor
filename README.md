# HTTP Security Headers & TLS Auditor

## Description
HTTP Security Headers & TLS Auditor is a Python-based cybersecurity tool that analyzes the security configuration of a website by inspecting its HTTP security headers and TLS certificate.

It helps identify missing security headers, checks certificate validity, calculates a basic security score, and generates recommendations to improve website security.

## Features

- **Custom URL Input:** Allows users to enter the website URL they want to audit.
- **URL Validation:** Performs basic URL format validation.
- **HTTP Security Header Inspection:** Checks for five important security headers:
  - Content-Security-Policy
  - Strict-Transport-Security
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
- **Security Score Calculation:** Calculates a score based on the presence of the five selected security headers.
- **TLS Certificate Inspection:** Retrieves certificate details, including subject, issuer, and validity dates.
- **Certificate Expiry Monitoring:** Checks certificate validity and calculates the remaining days before expiry.
- **Security Recommendations:** Suggests improvements for missing security headers.
- **Error Handling:** Handles invalid URLs, HTTP connection errors, timeouts, and TLS-related errors.
- **Final Audit Report:** Displays a summary of the website's HTTP and TLS security checks.

## Technologies Used

- Python
- Requests
- SSL
- Socket
- Certifi
- Tabulate
- Git and GitHub

## Project Structure

```text
http-security-headers-tls-auditor/
│
├── main.py
├── README.md
├── requirements.txt
├── .gitignore
└── venv/
```

## Installation and Setup

1. Clone the repository:

```bash
git clone https://github.com/gsambikag-star/http-security-headers-tls-auditor.git
```

2. Navigate to the project directory:

```bash
cd http-security-headers-tls-auditor
```

3. Create a virtual environment:

```bash
python -m venv venv
```

4. Activate the virtual environment on Windows:

```powershell
venv\Scripts\activate
```

5. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the following command:

```bash
python main.py
```

Enter the website URL when prompted.

Example:

```text
Enter website URL: example.com
```

The tool will inspect the website's HTTP security headers, analyze its TLS certificate, and generate a final security audit report.

## Sample Output

```text
======================================
       FINAL SECURITY AUDIT REPORT
======================================
Website: https://example.com
HTTP Status Code: 200

SECURITY HEADER SUMMARY
-----------------------------
Security Score: 0.0 %
Missing Headers: 5

TLS CERTIFICATE SUMMARY
-----------------------------
Certificate Status: VALID
Days Remaining: 38
======================================
```

*Note: The sample output is illustrative and may change depending on the website being audited and the certificate's validity period.*

## Disclaimer

This tool is intended for educational and authorized security assessment purposes only. Audit only websites that you own or have explicit permission to test.

## Author
- Ambika G.S