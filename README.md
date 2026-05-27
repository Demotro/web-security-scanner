# Web Security Scanner CLI

A simple command-line tool for basic web security checks.

## Features

- Checks if HTTPS is enabled
- Checks common HTTP security headers
- Shows HTTP status code
- Calculates a simple security score
- Supports JSON report export
- Handles connection errors and invalid URL input

## Checked Security Headers

- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

## Installation

Install required dependencies:

```bash
pip install -r requirements.txt
Usage

Basic scan:

python scanner.py https://example.com

On Windows, you can also use:

py scanner.py https://example.com

Scan with JSON export:

python scanner.py https://example.com --json report.json

or on Windows:

py scanner.py https://example.com --json report.json
Example Output
Web Security Scanner CLI
------------------------
Target: https://example.com
Status code: 200
[OK] HTTPS is enabled

Security headers:
[WARN] Content-Security-Policy is missing
[WARN] Strict-Transport-Security is missing
[WARN] X-Frame-Options is missing
[WARN] X-Content-Type-Options is missing
[WARN] Referrer-Policy is missing
[WARN] Permissions-Policy is missing

Security score: 1/7
Example JSON Report

The tool can export scan results into a JSON file:

py scanner.py https://example.com --json example_report.json
Technologies Used
Python
requests
argparse
JSON
HTTP security headers
Disclaimer

This tool is intended for educational purposes and basic security checks only.

Only scan websites that you own or have permission to test.